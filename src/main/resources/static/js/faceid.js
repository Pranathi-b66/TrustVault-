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

    // Anti-spoofing policy. A printed photograph or a screen replay is temporally inert: it never
    // blinks and its pixels barely change frame to frame. A live face does both.
    //
    // Sensitivity is a usability requirement as much as a security one. A natural blink lasts
    // 100-400 ms, so any cadence slower than ~100 ms samples a blink once or not at all: with the
    // old 90 ms sleep *plus* ~100 ms of detection the loop ran at ~5 Hz and only a slow,
    // deliberate squeeze was ever caught. The sleep is now only the remainder of each 35 ms slot,
    // so the loop runs as fast as detection allows (~10-15 Hz) with no dead time added.
    const LIVENESS = {
        WINDOW_MS: 20000,          // hard budget for the whole challenge
        SAMPLE_INTERVAL_MS: 35,    // tick cadence; detection time counts towards it
        BLINK_CLOSED_EAR: 0.21,    // fallback closure level until this face's baseline is learned
        BLINK_OPEN_EAR: 0.26,      // fallback reopened level until this face's baseline is learned
        BLINK_DROP_RATIO: 0.72,    // lids closed -> ratio falls to <= 72% of this face's open baseline
        BLINK_RECOVER_RATIO: 0.88, // lids open again -> ratio is back above 88% of that baseline
        BLINK_CLOSED_FRAMES: 2,    // a single shallow dip must not count as a blink
        BLINK_DEEP_DROP_RATIO: 0.60, // one frame this far below the baseline is a blink on its own
        MIN_POSE_DELTA: 0.05,      // normalised nose displacement: a small nod or head turn
        POSE_STRONG_DELTA: 0.10,   // one decisive movement is enough evidence on its own
        MIN_POSE_FRAMES: 2,
        MIN_FRAME_DELTA: 0.0004,   // mean luminance change between two consecutive frames
        MIN_ACTIVE_FRAMES: 2,
        MIN_SAMPLES: 6
    };

    // Environmental quality gate: a noisy vector is never submitted to the server.
    const QUALITY = {
        MIN_BRIGHTNESS: 0.28,
        MAX_BRIGHTNESS: 0.94,
        MIN_CONFIDENCE: 0.55,
        MIN_FACE_RATIO: 0.20,
        MAX_CENTRE_OFFSET: 0.18
    };

    let modelsPromise = null;
    let activeStream = null;
    let activeVideo = null;

    // Off-screen sampler used for brightness and frame-to-frame variance.
    let samplerCanvas = null;
    let samplerContext = null;
    let previousLuminance = null;

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
        previousLuminance = null;
    }

    // ---------------------------------------------------------------------
    // Frame analysis: brightness, optical variance, eye aspect ratio, head pose
    // ---------------------------------------------------------------------

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Waits only for the remainder of the current sampling slot. Detection itself takes 60-120 ms,
     * so sleeping a full interval on top of it halves the frame rate and is what made natural
     * blinks invisible to the challenge.
     */
    function pace(tickStart) {
        return sleep(Math.max(0, LIVENESS.SAMPLE_INTERVAL_MS - (Date.now() - tickStart)));
    }

    function distanceBetween(a, b) {
        return Math.hypot(a.x - b.x, a.y - b.y);
    }

    /**
     * Downsamples the current frame to 48x36 and reports mean luminance plus the mean absolute
     * change against the previous frame. A printed photo or a paused video produces a near-zero
     * delta, which is exactly what the liveness challenge needs to detect.
     */
    function sampleFrame(video) {
        if (!video || !video.videoWidth || !video.videoHeight) {
            return null;
        }
        const width = 48;
        const height = 36;
        if (!samplerCanvas) {
            samplerCanvas = document.createElement('canvas');
            samplerCanvas.width = width;
            samplerCanvas.height = height;
            samplerContext = samplerCanvas.getContext('2d', { willReadFrequently: true });
        }
        if (!samplerContext) {
            return null;
        }
        samplerContext.drawImage(video, 0, 0, width, height);
        const { data } = samplerContext.getImageData(0, 0, width, height);

        const luminance = new Float32Array(width * height);
        let total = 0;
        let delta = 0;
        for (let i = 0; i < luminance.length; i += 1) {
            const offset = i * 4;
            const value = (0.299 * data[offset] + 0.587 * data[offset + 1] + 0.114 * data[offset + 2]) / 255;
            luminance[i] = value;
            total += value;
            if (previousLuminance) {
                delta += Math.abs(value - previousLuminance[i]);
            }
        }
        const frameDelta = previousLuminance ? delta / luminance.length : 0;
        previousLuminance = luminance;

        return { brightness: total / luminance.length, frameDelta };
    }

    /** Eye aspect ratio of one eye: lids close -> the value collapses towards zero. */
    function eyeRatio(points) {
        if (!points || points.length < 6) {
            return 0;
        }
        const vertical = distanceBetween(points[1], points[5]) + distanceBetween(points[2], points[4]);
        const horizontal = distanceBetween(points[0], points[3]);
        return horizontal > 0 ? vertical / (2 * horizontal) : 0;
    }

    function eyeAspectRatio(landmarks) {
        const left = eyeRatio(landmarks.getLeftEye());
        const right = eyeRatio(landmarks.getRightEye());
        if (!left && !right) {
            return 0.3;
        }
        return (left + right) / 2;
    }

    /** Yaw/pitch proxy: where the nose tip sits relative to the eye line, in interocular units. */
    function headPose(points) {
        const nose = points[30];
        const leftEye = points[36];
        const rightEye = points[45];
        if (!nose || !leftEye || !rightEye) {
            return { yaw: 0, pitch: 0 };
        }
        const eyeMidX = (leftEye.x + rightEye.x) / 2;
        const eyeMidY = (leftEye.y + rightEye.y) / 2;
        const interocular = distanceBetween(leftEye, rightEye) || 1;
        return {
            yaw: (nose.x - eyeMidX) / interocular,
            pitch: (nose.y - eyeMidY) / interocular
        };
    }

    /** One lightweight pass (landmarks only, no 128-d embedding) used by the liveness loop. */
    async function observe(video) {
        const lib = requireApi();
        const detection = await lib
            .detectSingleFace(video, new lib.TinyFaceDetectorOptions(DETECTOR_OPTIONS))
            .withFaceLandmarks();
        if (!detection) {
            return null;
        }
        const box = detection.detection.box;
        const sample = sampleFrame(video);
        return {
            confidence: Number(detection.detection.score || 0),
            box: { x: box.x, y: box.y, width: box.width, height: box.height },
            ear: eyeAspectRatio(detection.landmarks),
            pose: headPose(detection.landmarks.positions),
            brightness: sample ? sample.brightness : 0.5,
            frameDelta: sample ? sample.frameDelta : 0
        };
    }

    /**
     * Environmental gate applied before a descriptor may leave the browser. Returns the concrete
     * instructions to show the user instead of silently submitting a weak vector.
     */
    function assessQuality(snapshot, video) {
        if (!snapshot) {
            return { ok: false, issues: ['No face detected. Center face in frame.'] };
        }
        const issues = [];
        if (snapshot.confidence < QUALITY.MIN_CONFIDENCE) {
            issues.push('Hold still: face detection confidence is too low.');
        }
        if (snapshot.brightness < QUALITY.MIN_BRIGHTNESS) {
            issues.push('Adjust lighting: your face is too dark.');
        } else if (snapshot.brightness > QUALITY.MAX_BRIGHTNESS) {
            issues.push('Adjust lighting: the frame is over-exposed.');
        }
        const frameHeight = video && video.videoHeight ? video.videoHeight : 0;
        if (frameHeight && snapshot.box.height / frameHeight < QUALITY.MIN_FACE_RATIO) {
            issues.push('Move closer: your face is too small in the frame.');
        }
        if (!isCentred(snapshot, video)) {
            issues.push('Center face in frame.');
        }
        return { ok: issues.length === 0, issues };
    }

    /**
     * Builds the live prompt shown while the challenge is running. The outstanding action is
     * always the first clause; environmental advice is appended so it can never mask it.
     */
    function livenessInstruction(blinkDetected, liveMotion, quality, posePeak) {
        let action;
        if (blinkDetected) {
            action = 'Liveness confirmed. Hold still while the descriptor is captured...';
        } else if (liveMotion) {
            action = 'Head movement detected. Hold still while the descriptor is captured...';
        } else if (posePeak >= LIVENESS.MIN_POSE_DELTA) {
            action = 'Keep turning your head slightly left or right.';
        } else {
            action = 'Turn your head slightly left or right to verify liveness.';
        }
        const hint = quality && !quality.ok && quality.issues.length ? ' ' + quality.issues[0] : '';
        return action + hint;
    }

    /**
     * Anti-spoofing challenge. A static photograph or a paused screen replay cannot blink, cannot
     * move its head and does not change pixels between frames, so this loop refuses to release a
     * descriptor until it has seen, over at least six samples:
     *
     * <ul>
     *   <li>a completed blink, measured against this face's own open-eye baseline; <b>or</b></li>
     *   <li>a deliberate nod (nose displacement) accompanied by real frame-to-frame variance.</li>
     * </ul>
     *
     * @returns {Promise<{passed:boolean, blinkDetected:boolean, poseFrames:number,
     *                    activeFrames:number, samples:number, durationMs:number}>}
     */
    async function runLiveness(video, { onProgress, shouldStop } = {}) {
        const startedAt = Date.now();
        const report = update => {
            if (typeof onProgress === 'function') {
                onProgress(update);
            }
        };

        let samples = 0;
        let eyesClosed = false;
        let closedStreak = 0;
        let blinkDetected = false;
        let poseFrames = 0;
        let posePeak = 0;
        let activeFrames = 0;
        let baseline = null;
        let openBaseline = 0;

        report({ stage: 'blink', blinkDetected: false, message: 'Liveness check: turn your head slightly left or right.' });

        while (Date.now() - startedAt < LIVENESS.WINDOW_MS) {
            if (typeof shouldStop === 'function' && shouldStop()) {
                throw new Error('Liveness check cancelled.');
            }

            const tickStart = Date.now();
            const frame = await observe(video).catch(() => null);
            if (!frame) {
                report({ stage: 'searching', blinkDetected: false, message: 'No face detected. Center face in frame.' });
                await pace(tickStart);
                continue;
            }

            samples += 1;

            // Blink detection on this face's own scale. An absolute ratio is unreliable at webcam
            // resolution (the 68 landmark points are noisy and eye shape varies), so the widest
            // opening seen so far becomes the personal baseline and a lid has to fall well below
            // it before the closure counts. A photograph never closes an eye at all.
            if (!eyesClosed && frame.ear > openBaseline) {
                openBaseline = frame.ear;
            }
            const usableBaseline = openBaseline >= 0.14 ? openBaseline : 0;
            const closedLimit = usableBaseline
                ? usableBaseline * LIVENESS.BLINK_DROP_RATIO
                : LIVENESS.BLINK_CLOSED_EAR;
            const openLimit = usableBaseline
                ? usableBaseline * LIVENESS.BLINK_RECOVER_RATIO
                : LIVENESS.BLINK_OPEN_EAR;

            if (!blinkDetected) {
                if (frame.ear <= closedLimit) {
                    closedStreak += 1;
                    // Two consecutive samples are the normal proof. A deep closure counts on its
                    // own: at 10-15 samples per second a quick blink can land a single frame
                    // inside the dip, and demanding a second one is what made fast blinks vanish.
                    const deep = usableBaseline
                        ? frame.ear <= usableBaseline * LIVENESS.BLINK_DEEP_DROP_RATIO
                        : frame.ear <= LIVENESS.BLINK_CLOSED_EAR * 0.75;
                    if (closedStreak >= LIVENESS.BLINK_CLOSED_FRAMES || deep) {
                        eyesClosed = true;
                    }
                } else {
                    closedStreak = 0;
                    if (eyesClosed && frame.ear >= openLimit) {
                        blinkDetected = true;
                        eyesClosed = false;
                    }
                }
            }

            if (!baseline) {
                baseline = frame.pose;
            } else {
                const yaw = Math.abs(frame.pose.yaw - baseline.yaw);
                const pitch = Math.abs(frame.pose.pitch - baseline.pitch);
                const delta = Math.max(yaw, pitch);
                posePeak = Math.max(posePeak, delta);
                if (delta >= LIVENESS.MIN_POSE_DELTA) {
                    poseFrames += 1;
                } else if (delta < LIVENESS.MIN_POSE_DELTA * 0.6) {
                    // Nearly still: let the reference follow slow posture drift (the user relaxing
                    // into the chair) so that drift cannot later be mistaken for a deliberate
                    // movement, and a genuine nod still stands out against the current pose.
                    baseline = {
                        yaw: baseline.yaw * 0.9 + frame.pose.yaw * 0.1,
                        pitch: baseline.pitch * 0.9 + frame.pose.pitch * 0.1
                    };
                }
            }

            if (frame.frameDelta >= LIVENESS.MIN_FRAME_DELTA) {
                activeFrames += 1;
            }

            // The fallback proof is a small nod or head turn *and* visible pixel change. Two
            // samples above the gentle threshold, or one decisive movement, are both enough: a
            // quick nod can fall between samples, and a still image can produce neither.
            const liveMotion = (poseFrames >= LIVENESS.MIN_POSE_FRAMES
                || posePeak >= LIVENESS.POSE_STRONG_DELTA)
                && activeFrames >= LIVENESS.MIN_ACTIVE_FRAMES;
            const quality = assessQuality(frame, video);

            // The instruction always leads with the action that is still outstanding. An
            // environmental hint is appended, never substituted: hiding "blink" behind "adjust
            // lighting" leaves the user staring at the camera wondering why nothing happens.
            report({
                stage: blinkDetected ? 'motion' : 'blink',
                blinkDetected,
                liveMotion,
                qualityOk: quality.ok,
                message: livenessInstruction(blinkDetected, liveMotion, quality, posePeak)
            });

            if (samples >= LIVENESS.MIN_SAMPLES && (blinkDetected || liveMotion)) {
                return {
                    passed: true,
                    blinkDetected,
                    poseFrames,
                    posePeak,
                    activeFrames,
                    samples,
                    durationMs: Date.now() - startedAt
                };
            }

            await pace(tickStart);
        }

        return {
            passed: false,
            blinkDetected,
            poseFrames,
            posePeak,
            activeFrames,
            samples,
            durationMs: Date.now() - startedAt
        };
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

    /** Frames averaged into one descriptor: a single frame carries sensor and landmark noise. */
    const CAPTURE_FRAMES = 5;
    const CAPTURE_FRAME_GAP_MS = 90;

    /** Component-wise mean of several embeddings of the same face. */
    function averageDescriptors(frames) {
        const mean = new Array(frames[0].length).fill(0);
        for (const frame of frames) {
            for (let i = 0; i < mean.length; i += 1) {
                mean[i] += frame[i];
            }
        }
        for (let i = 0; i < mean.length; i += 1) {
            mean[i] /= frames.length;
        }
        return mean;
    }

    /**
     * Final capture, pooled over several consecutive frames. The descriptor is only returned when
     * the environment passes the quality gate, so a dark, off-centre or low-confidence frame can
     * never be submitted to the server as if it were a usable biometric sample.
     *
     * <p>Averaging matters for the identity decision: one frame of a genuine face can drift 0.05
     * or more from the enrolled template purely from exposure and landmark jitter, which is
     * enough to move it across a distance ceiling. Pooling five frames pulls the probe back
     * towards the face's true embedding. Frames the detector missed are skipped, and a single
     * good frame still yields a usable capture.</p>
     */
    async function captureDescriptor(video) {
        const frames = [];
        let latest = null;
        for (let i = 0; i < CAPTURE_FRAMES; i += 1) {
            const capture = await detect(video);
            if (capture && capture.descriptor.length === DESCRIPTOR_SIZE) {
                frames.push(capture.descriptor);
                latest = capture;
            }
            if (i < CAPTURE_FRAMES - 1) {
                await new Promise(resolve => setTimeout(resolve, CAPTURE_FRAME_GAP_MS));
            }
        }
        if (!latest) {
            throw new Error('No face detected. Center face in frame, adjust lighting and try again.');
        }
        const sample = sampleFrame(video);
        const descriptor = frames.length === 1 ? frames[0] : averageDescriptors(frames);
        const quality = assessQuality(
            { ...latest, descriptor, brightness: sample ? sample.brightness : 0.5 },
            video
        );
        if (!quality.ok) {
            const error = new Error(quality.issues[0]);
            error.qualityIssues = quality.issues;
            throw error;
        }
        return { ...latest, descriptor, quality };
    }

    return {
        DESCRIPTOR_SIZE,
        MODEL_URL,
        LIVENESS,
        QUALITY,
        loadModels,
        startCamera,
        stopCamera,
        detect,
        observe,
        isCentred,
        assessQuality,
        runLiveness,
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
            info: 'text-teal-700 bg-slate-50 border-teal-200',
            error: 'text-rose-700 bg-rose-50 border-rose-200',
            success: 'text-emerald-700 bg-emerald-50 border-emerald-200'
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

    /** Transient label used to put the current liveness instruction on the button itself. */
    function setButtonState(label, icon) {
        const ui = elements();
        if (!ui.button) {
            return;
        }
        ui.button.innerHTML = `<i class="fa-solid ${icon || 'fa-spinner'}"></i><span>${label}</span>`;
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
        // While a failure message is on screen the 600 ms alignment poll stays quiet, otherwise
        // it replaces the message before it can be read.
        let suppressGuidanceUntil = 0;

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
                setButtonState('Turn head', 'fa-eye');
                try {
                    // 1. Anti-spoofing. A printed photo or a paused screen replay cannot blink,
                    //    nod or change its pixels, so no descriptor is generated until the
                    //    challenge has been satisfied on the live feed. The instruction is pushed
                    //    to the button, the subtitle and the status strip: a prompt hidden in one
                    //    small line is effectively never seen.
                    const liveness = await FaceIDEngine.runLiveness(ui.video, {
                        shouldStop: () => closed,
                        onProgress: update => {
                            setStatus(update.message, 'info');
                            ui.subtitle.textContent = update.message;
                            setButtonState(update.blinkDetected ? 'Hold still…' : 'Turn head', 'fa-eye');
                        }
                    });
                    if (!liveness.passed) {
                        throw new Error(liveness.blinkDetected || liveness.posePeak > 0.02
                            ? 'Liveness check failed: a slight head turn opens the gate — try once more.'
                            : 'Liveness check failed: no head movement was detected. Static photos and screen replays are rejected.');
                    }

                    // 2. Capture, guarded by the lighting / framing quality gate.
                    ui.button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Capturing descriptor...</span>';
                    setStatus('Liveness confirmed. Capturing your facial descriptor...', 'success');
                    const capture = await FaceIDEngine.captureDescriptor(ui.video);
                    highlightGuide(true);
                    setStatus(capture.descriptor.length === FaceIDEngine.DESCRIPTOR_SIZE
                        ? 'Descriptor captured. Verifying with the server...'
                        : 'Unexpected descriptor. Retry the scan.', 'info');

                    // 3. Verify against the timestamped challenge issued for this action.
                    const result = await verify(capture);
                    close();
                    resolve(result);
                } catch (error) {
                    // Keep the failure on screen long enough to be read.
                    suppressGuidanceUntil = Date.now() + 5000;
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
                    setStatus('Align your face within the frame, then press Scan Face. You will be asked to turn your head slightly left or right.', 'info');
                    guidanceTimer = setInterval(async () => {
                        if (busy || closed || Date.now() < suppressGuidanceUntil) {
                            return;
                        }
                        try {
                            const snapshot = await FaceIDEngine.observe(ui.video);
                            if (closed) {
                                return;
                            }
                            // Real-time environmental feedback: "Adjust lighting" or "Center face
                            // in frame" is far more useful than a generic "scan failed" later.
                            const quality = FaceIDEngine.assessQuality(snapshot, ui.video);
                            if (!quality.ok) {
                                highlightGuide(false);
                                setStatus(quality.issues[0], 'info');
                            } else {
                                highlightGuide(true);
                                setStatus('Face aligned and well lit. Press Scan Face, then turn your head slightly left or right.', 'success');
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
            subtitle: subtitle || 'Look at the camera, turn your head slightly left or right when prompted, then press Scan Face to capture your facial descriptor.',
            actionLabel: actionLabel || 'Scan Face',
            verify: async capture => capture
        });
    }

    /**
     * Action-time gate: capture a live face, request a timestamped challenge, and exchange both
     * for an action token.
     *
     * <p>The challenge is requested <b>after</b> the capture, immediately before submission. It
     * is bound to this user, this document and this action, expires after 30 seconds and can be
     * redeemed only once. Minting it earlier would let camera start-up, the model download and
     * the 20 s liveness window age the nonce out, and every aged-out attempt would look like an
     * attack in the audit trail.</p>
     */
    async function authorize(action, documentId) {
        const effectiveAction = (action || 'DOWNLOAD').toUpperCase();
        const purpose = effectiveAction === 'EDIT' ? 'edit this document' : 'download this document';

        return prompt({
            title: 'Facial Verification',
            subtitle: `Scan your enrolled face to ${purpose}. Press "Scan & Verify", then turn your head slightly left or right when asked: a photo or a screen replay cannot pass the liveness check.`,
            actionLabel: 'Scan & Verify',
            verify: async capture => {
                let challenge;
                try {
                    challenge = await API.getBiometricChallenge(documentId, effectiveAction);
                } catch (error) {
                    throw new Error(error.message
                        || 'Unable to obtain a FaceID challenge. Refresh the page and retry.');
                }
                if (!challenge || !challenge.challengeToken) {
                    throw new Error('The server did not return a FaceID challenge. Retry the scan.');
                }

                const result = await API.verifyFace(
                    documentId, effectiveAction, capture.descriptor, challenge.challengeToken);

                setStatus(`Match confirmed (distance ${Number(result.distance ?? 0).toFixed(3)} ≤ ${Number(result.threshold ?? 0).toFixed(2)}).`, 'success');
                return result.faceToken;
            }
        });
    }

    /** Enrollment-time binding: captures the face and posts it to /api/auth/biometric/register-face. */
    function enroll(email, { mandatory = false } = {}) {
        return prompt({
            title: mandatory ? 'Mandatory Webcam FaceID Enrollment' : 'Enroll Face',
            subtitle: 'Your account is bound to exactly one face. Press the button, then turn your head slightly left or right when asked — a face already used by another account is rejected.',
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
