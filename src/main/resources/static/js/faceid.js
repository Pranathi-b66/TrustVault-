// TrustVault Webcam FaceID Engine
//
// Captures a live facial embedding with face-api.js (TinyFaceDetector + 68 landmarks +
// FaceRecognitionNet). The 128-value descriptor is the only thing the server ever receives:
// no image, no video frame and no cached credential leaves the browser.
//
// Every scan requires the user to start the camera and press "Scan Face" - there is no
// silent OS/browser credential path that could satisfy the gate without a live face.

const FaceIDEngine = (() => {
    const MODEL_URL = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/model';
    const DESCRIPTOR_SIZE = 128;
    const DETECTOR_OPTIONS = { inputSize: 320, scoreThreshold: 0.45 };

    let modelsPromise = null;
    let activeStream = null;
    let activeVideo = null;

    function api() {
        return window.faceapi || null;
    }

    function requireApi() {
        const lib = api();
        if (!lib) {
            throw new Error('The face recognition library could not be loaded. Check the network connection and retry.');
        }
        return lib;
    }

    /** Loads the three model bundles once; a failed attempt may be retried by the caller. */
    function loadModels() {
        if (modelsPromise) {
            return modelsPromise;
        }
        modelsPromise = (async () => {
            const lib = requireApi();
            await lib.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
            await lib.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
            await lib.nets.faceRecognitionNet.loadFromUri(MODEL_URL);
            return true;
        })().catch(error => {
            modelsPromise = null;
            throw error;
        });
        return modelsPromise;
    }

    async function startCamera(video) {
        if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
            throw new Error('This browser does not expose a camera API. Use a browser with getUserMedia support.');
        }
        const stream = await navigator.mediaDevices.getUserMedia({
            audio: false,
            video: {
                facingMode: 'user',
                width: { ideal: 640 },
                height: { ideal: 480 }
            }
        });
        video.srcObject = stream;
        video.muted = true;
        video.setAttribute('playsinline', 'true');
        await video.play();
        activeStream = stream;
        activeVideo = video;
        return stream;
    }

    function stopCamera() {
        if (activeStream) {
            activeStream.getTracks().forEach(track => track.stop());
        }
        if (activeVideo) {
            activeVideo.srcObject = null;
        }
        activeStream = null;
        activeVideo = null;
    }

    /** Runs one detection pass; returns null when no face is present. */
    async function detect(video) {
        const lib = requireApi();
        const detection = await lib.detectSingleFace(
            video, new lib.TinyFaceDetectorOptions(DETECTOR_OPTIONS))
            .withFaceLandmarks()
            .withFaceDescriptor();
        if (!detection) {
            return null;
        }
        const box = detection.detection.box;
        return {
            descriptor: Array.from(detection.descriptor),
            confidence: Number(detection.detection.score || 0),
            box: { x: box.x, y: box.y, width: box.width, height: box.height }
        };
    }

    /** True when the detected face is roughly centred in the guide. */
    function isCentred(capture, video) {
        if (!capture || !video || !video.videoWidth || !video.videoHeight) {
            return false;
        }
        const centreX = capture.box.x + capture.box.width / 2;
        const centreY = capture.box.y + capture.box.height / 2;
        const dx = Math.abs(centreX - video.videoWidth / 2) / video.videoWidth;
        const dy = Math.abs(centreY - video.videoHeight / 2) / video.videoHeight;
        return dx < 0.18 && dy < 0.18;
    }

    async function captureDescriptor(video) {
        const capture = await detect(video);
        if (!capture) {
            throw new Error('No face detected. Centre your face inside the oval, improve the lighting and try again.');
        }
        if (capture.descriptor.length !== DESCRIPTOR_SIZE) {
            throw new Error('The face model returned an unexpected descriptor size. Reload the page and retry.');
        }
        return capture;
    }

    return {
        DESCRIPTOR_SIZE,
        MODEL_URL,
        loadModels,
        startCamera,
        stopCamera,
        detect,
        isCentred,
        captureDescriptor,
        isReady: () => !!modelsPromise
    };
})();

// =============================================================================
// Modal orchestration (shared by enrollment and action-time verification)
// =============================================================================
const FaceIDUX = (() => {
    const MODAL_ID = 'modal-face-prompt';
    const VIDEO_ID = 'face-camera';
    const GUIDE_ID = 'face-guide';
    const STATUS_ID = 'face-status-msg';
    const BUTTON_ID = 'btn-run-face-scan';

    let busy = false;
    let cancelPending = null;

    function elements() {
        return {
            modal: document.getElementById(MODAL_ID),
            video: document.getElementById(VIDEO_ID),
            guide: document.getElementById(GUIDE_ID),
            status: document.getElementById(STATUS_ID),
            button: document.getElementById(BUTTON_ID),
            title: document.getElementById('face-prompt-title-text'),
            subtitle: document.getElementById('face-prompt-subtitle')
        };
    }

    function setStatus(text, tone) {
        const ui = elements();
        if (!ui.status) {
            return;
        }
        const tones = {
            info: 'text-teal-300 bg-slate-950 border-teal-800',
            error: 'text-rose-300 bg-rose-950/50 border-rose-800',
            success: 'text-emerald-300 bg-emerald-950/50 border-emerald-800'
        };
        ui.status.textContent = text;
        ui.status.className = `text-xs font-mono p-2.5 rounded-xl border ${tones[tone] || tones.info}`;
    }

    function highlightGuide(active) {
        const ui = elements();
        const oval = ui.guide ? ui.guide.querySelector('div') : null;
        if (!oval) {
            return;
        }
        oval.classList.toggle('border-emerald-400', active);
        oval.classList.toggle('border-teal-400', !active);
    }

    function resetButton(label) {
        const ui = elements();
        ui.button.disabled = false;
        ui.button.innerHTML = `<i class="fa-solid fa-camera"></i><span>${label}</span>`;
    }

    /**
     * Opens the camera modal and resolves with whatever {@code verify} returns once a live
     * descriptor has been captured and accepted by the server.
     *
     * @param {object} options
     * @param {string} options.title       modal heading
     * @param {string} options.subtitle    explanation shown to the user
     * @param {string} options.actionLabel label of the capture button
     * @param {Function} options.verify    async ({descriptor, confidence, box}) => result
     */
    function prompt({ title, subtitle, actionLabel, verify }) {
        const ui = elements();
        if (!ui.modal || !ui.video) {
            return Promise.reject(new Error('The webcam prompt is unavailable on this page.'));
        }

        ui.title.textContent = title;
        ui.subtitle.textContent = subtitle;
        resetButton(actionLabel);
        ui.button.disabled = true;
        setStatus('Requesting camera access...', 'info');
        highlightGuide(false);
        ui.modal.classList.remove('hidden');

        let stream = null;
        let guidanceTimer = null;
        let closed = false;

        // Assigned inside the promise executor once the handlers exist.
        let detach = () => {};

        const stopEverything = () => {
            if (guidanceTimer) {
                clearInterval(guidanceTimer);
                guidanceTimer = null;
            }
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
                stream = null;
            }
            FaceIDEngine.stopCamera();
            ui.video.srcObject = null;
        };

        const close = () => {
            closed = true;
            cancelPending = null;
            detach();
            stopEverything();
            ui.modal.classList.add('hidden');
        };

        return new Promise((resolve, reject) => {
            cancelPending = () => {
                closed = true;
                detach();
                stopEverything();
                cancelPending = null;
                ui.modal.classList.add('hidden');
                reject(new Error('Face verification cancelled. Action aborted.'));
            };

            const beginCapture = async event => {
                if (event && event.isTrusted === false) {
                    return;
                }
                if (busy || closed) {
                    return;
                }
                busy = true;
                ui.button.disabled = true;
                ui.button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Scanning face...</span>';
                try {
                    setStatus('Extracting facial descriptor...', 'info');
                    const capture = await FaceIDEngine.captureDescriptor(ui.video);
                    highlightGuide(true);
                    setStatus(capture.descriptor.length === FaceIDEngine.DESCRIPTOR_SIZE
                        ? 'Descriptor captured. Verifying with the server...'
                        : 'Unexpected descriptor. Retry the scan.', 'info');

                    const result = await verify(capture);
                    close();
                    resolve(result);
                } catch (error) {
                    setStatus(error.message || 'Face capture failed.', 'error');
                    resetButton(actionLabel);
                    ui.button.disabled = false;
                } finally {
                    busy = false;
                }
            };

            const onKeyDown = event => {
                if (event.key !== ' ' && event.key !== 'Enter') {
                    return;
                }
                if (event.repeat) {
                    return;
                }
                event.preventDefault();
                beginCapture(event);
            };

            ui.button.addEventListener('click', beginCapture);
            ui.button.addEventListener('keydown', onKeyDown);
            detach = () => {
                ui.button.removeEventListener('click', beginCapture);
                ui.button.removeEventListener('keydown', onKeyDown);
            };

            // Camera first, models in parallel: the preview appears as soon as possible.
            const modelsReady = FaceIDEngine.loadModels();
            FaceIDEngine.startCamera(ui.video).then(active => {
                if (closed) {
                    active.getTracks().forEach(track => track.stop());
                    return;
                }
                stream = active;
                setStatus('Align your face within the frame. Loading the recognition model...', 'info');
                return modelsReady.then(() => {
                    if (closed) {
                        return;
                    }
                    resetButton(actionLabel);
                    setStatus('Align your face within the frame, then press Scan Face.', 'info');
                    guidanceTimer = setInterval(async () => {
                        if (busy || closed) {
                            return;
                        }
                        try {
                            const capture = await FaceIDEngine.detect(ui.video);
                            if (closed) {
                                return;
                            }
                            if (!capture) {
                                highlightGuide(false);
                                setStatus('No face detected. Centre your face inside the oval.', 'info');
                            } else if (!FaceIDEngine.isCentred(capture, ui.video)) {
                                highlightGuide(false);
                                setStatus('Face detected. Move a little closer to the centre.', 'info');
                            } else {
                                highlightGuide(true);
                                setStatus('Face aligned. Press Scan Face to verify.', 'success');
                            }
                        } catch (error) {
                            setStatus(error.message || 'Face detection is unavailable.', 'error');
                        }
                    }, 600);
                });
            }).catch(error => {
                const message = error && error.name === 'NotAllowedError'
                    ? 'Camera access was denied. Allow camera permission for this site and retry.'
                    : (error.message || 'The camera could not be started.');
                setStatus(message, 'error');
                modelsReady.catch(() => {});
            });
        });
    }

    /** Captures a descriptor without server verification (sign-up, where no account exists yet). */
    function capture({ title, subtitle, actionLabel } = {}) {
        return prompt({
            title: title || 'Webcam FaceID Capture',
            subtitle: subtitle || 'Look at the camera and press Scan Face to capture your facial descriptor.',
            actionLabel: actionLabel || 'Scan Face',
            verify: async capture => capture
        });
    }

    /** Action-time gate: capture, match against the caller's enrollment, return the action token. */
    function authorize(action, documentId) {
        const effectiveAction = (action || 'DOWNLOAD').toUpperCase();
        const purpose = effectiveAction === 'EDIT' ? 'edit this document' : 'download this document';

        return prompt({
            title: 'Facial Verification',
            subtitle: `Scan your enrolled face to ${purpose}. The server compares it against your descriptor only.`,
            actionLabel: 'Scan & Verify',
            verify: async capture => {
                const result = await API.verifyFace(documentId, effectiveAction, capture.descriptor);
                setStatus(`Match confirmed (similarity ${Number(result.score ?? 0).toFixed(3)} ≥ ${Number(result.threshold ?? 0).toFixed(2)}).`, 'success');
                return result.faceToken;
            }
        });
    }

    /** Enrollment-time binding: captures the face and posts it to /api/auth/biometric/register-face. */
    function enroll(email, { mandatory = false } = {}) {
        return prompt({
            title: mandatory ? 'Mandatory Webcam FaceID Enrollment' : 'Enroll Face',
            subtitle: 'Your account is bound to exactly one face. A face already used by another account is rejected.',
            actionLabel: 'Capture & Bind Face',
            verify: async capture => {
                const result = await API.registerFace(email, capture.descriptor, 'webcam');
                setStatus('Face descriptor bound to your account.', 'success');
                return result;
            }
        });
    }

    function cancel() {
        if (typeof cancelPending === 'function') {
            const reject = cancelPending;
            cancelPending = null;
            reject();
        }
    }

    return { capture, authorize, enroll, cancel, prompt };
})();
