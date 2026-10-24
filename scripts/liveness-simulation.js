// Headless simulation of the FaceID liveness state machine.
//
// The challenge runs in the browser against a real camera, so this harness feeds the exact
// shipped src/main/resources/static/js/faceid.js through a stubbed face-api.js: each scripted
// frame carries an eye-aspect-ratio and a nose pitch, and the asserts below pin the sensitivity
// that a user actually experiences.
//
//   node scripts/liveness-simulation.js
//
// Scenarios:
//   1. static photo            -> must fail (no blink, no movement)
//   2. normal blink (shallow)  -> must pass on two consecutive closed frames
//   3. quick blink (one frame) -> must pass on a single deep closure
//   4. small nod (0.06 pitch)  -> must pass without a whole-body movement
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = path.join(__dirname, '..', 'src', 'main', 'resources', 'static', 'js', 'faceid.js');
const VIDEO = { videoWidth: 640, videoHeight: 480 };

function eyePoints(originX, originY, ear) {
    // eyeRatio = (|p1-p5| + |p2-p4|) / (2 * |p0-p3|); width 40 and v = ear * 20 give exactly ear.
    const v = ear * 20;
    return [
        { x: originX, y: originY },
        { x: originX + 10, y: originY - v },
        { x: originX + 30, y: originY - v },
        { x: originX + 40, y: originY },
        { x: originX + 30, y: originY + v },
        { x: originX + 10, y: originY + v }
    ];
}

function landmarksFor(ear, pitch) {
    const positions = new Array(68).fill(null).map(() => ({ x: 0, y: 0 }));
    const left = eyePoints(200, 150, ear);
    const right = eyePoints(240, 150, ear);
    left.forEach((point, i) => { positions[36 + i] = point; });
    right.forEach((point, i) => { positions[42 + i] = point; });
    // headPose reads the nose tip against the eye line: 80 px interocular, so pitch * 80 px.
    positions[30] = { x: 240, y: 150 + pitch * 80 };
    return {
        positions,
        getLeftEye: () => positions.slice(36, 42),
        getRightEye: () => positions.slice(42, 48)
    };
}

function makeSandbox(frames) {
    let index = 0;
    let brightness = 0.5;

    const faceapi = {
        nets: {
            tinyFaceDetector: { loadFromUri: async () => {} },
            faceLandmark68Net: { loadFromUri: async () => {} },
            faceRecognitionNet: { loadFromUri: async () => {} }
        },
        TinyFaceDetectorOptions: function TinyFaceDetectorOptions() {},
        detectSingleFace: () => {
            const build = async () => {
                if (index >= frames.length) {
                    return null;
                }
                const frame = frames[index];
                index += 1;
                // Alternate the sampled luminance so consecutive frames show real pixel change.
                brightness = brightness === 0.5 ? 0.9 : 0.5;
                return {
                    detection: { score: 0.92, box: { x: 160, y: 90, width: 320, height: 300 } },
                    landmarks: landmarksFor(frame.ear, frame.pitch),
                    descriptor: new Float32Array(128)
                };
            };
            return {
                withFaceLandmarks: async () => build(),
                withFaceDescriptor: async () => build()
            };
        }
    };

    const canvas = {
        width: 0,
        height: 0,
        getContext: () => ({
            drawImage: () => {},
            getImageData: () => {
                const value = Math.round(brightness * 255);
                const data = new Uint8ClampedArray(48 * 36 * 4);
                for (let i = 0; i < data.length; i += 4) {
                    data[i] = value;
                    data[i + 1] = value;
                    data[i + 2] = value;
                    data[i + 3] = 255;
                }
                return { data };
            }
        })
    };

    const sandbox = {
        window: { faceapi },
        document: { createElement: () => canvas, getElementById: () => null },
        navigator: { mediaDevices: {} },
        setTimeout,
        clearTimeout,
        console
    };
    sandbox.globalThis = sandbox;
    return sandbox;
}

async function run(name, frames, expect) {
    const context = vm.createContext(makeSandbox(frames));
    vm.runInContext(fs.readFileSync(SOURCE, 'utf8'), context, { filename: 'faceid.js' });
    const engine = vm.runInContext('FaceIDEngine', context);
    // Fast, short challenge so the harness finishes in milliseconds.
    engine.LIVENESS.WINDOW_MS = 900;
    engine.LIVENESS.SAMPLE_INTERVAL_MS = 5;

    const result = await engine.runLiveness(VIDEO, {});
    const actual = {
        passed: result.passed,
        blink: result.blinkDetected,
        poseFrames: result.poseFrames,
        posePeak: Number(result.posePeak.toFixed(3)),
        samples: result.samples
    };
    const ok = actual.passed === expect.passed
        && (expect.blink === undefined || actual.blink === expect.blink);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${JSON.stringify(actual)}`);
    if (!ok) {
        process.exitCode = 1;
    }
}

(async () => {
    const hold = (count, ear, pitch) => new Array(count).fill(null).map(() => ({ ear, pitch }));

    await run('static photo (no blink, no movement)', hold(60, 0.3, 0), { passed: false, blink: false });

    await run('normal blink, two closed frames', [
        ...hold(3, 0.3, 0), ...hold(2, 0.205, 0), ...hold(20, 0.3, 0)
    ], { passed: true, blink: true });

    await run('quick blink, one deep frame', [
        ...hold(3, 0.3, 0), { ear: 0.16, pitch: 0 }, ...hold(20, 0.3, 0)
    ], { passed: true, blink: true });

    await run('small nod, 0.06 pitch', [
        ...hold(3, 0.3, 0), ...hold(2, 0.3, 0.06), ...hold(20, 0.3, 0)
    ], { passed: true, blink: false });

    await run('tiny drift, 0.02 pitch', hold(60, 0.3, 0.02), { passed: false, blink: false });
})().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
