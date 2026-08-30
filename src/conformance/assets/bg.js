/**
 * Conformance page background: the suite running.
 *
 * Each vertical lane is one test port. Connections descend a lane, meet the
 * anomaly line partway down, and resolve there into one of the three things a
 * run can produce:
 *
 *   - carried on            → continues to the bottom, in the pass colour
 *   - rejected it           → stops just below the line and marks the spot
 *   - never reached it      → fades out grey, proving nothing either way
 *
 * The third is drawn as prominently as the other two on purpose: an
 * inconclusive result is an outcome the suite reports, not an absence.
 *
 * Runs by default; the corner toggle stops it.
 */
(function () {
    'use strict';

    const canvas = document.getElementById('cf-bg-canvas');
    if (!canvas || !canvas.getContext) {
        return;
    }

    const ctx = canvas.getContext('2d');
    const STORAGE_KEY = 'pqc-conformance-motion';

    /** The lowest UDP port the suite binds, so the lane labels are the real ones. */
    const FIRST_PORT = 4460;

    const PASS = 'rgba(92, 193, 145, ';
    const REJECT = 'rgba(240, 134, 141, ';
    const NEUTRAL = 'rgba(127, 143, 157, ';
    const LINE = 'rgba(70, 181, 203, ';

    const OUTCOMES = ['pass', 'pass', 'pass', 'pass', 'reject', 'reject', 'inconclusive'];

    let width = 0;
    let height = 0;
    let dpr = 1;
    let lanes = [];
    let anomalyY = 0;
    let runs = [];
    let rafId = null;
    let running = true;
    let lastSpawn = 0;
    let last = 0;

    function resize() {
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        // Lane spacing is chosen from the viewport rather than fixed, so a narrow
        // window gets fewer, wider lanes instead of an unreadable smear.
        const count = Math.max(6, Math.min(22, Math.floor(width / 86)));
        const gap = width / (count + 1);
        lanes = [];
        for (let i = 0; i < count; i += 1) {
            lanes.push(gap * (i + 1));
        }

        anomalyY = height * 0.42;
        runs = [];
    }

    function spawn() {
        if (lanes.length === 0) {
            return;
        }
        const lane = Math.floor(Math.random() * lanes.length);
        runs.push({
            lane: lane,
            y: -12,
            speed: 0.045 + Math.random() * 0.05,
            outcome: OUTCOMES[Math.floor(Math.random() * OUTCOMES.length)],
            // Assigned only once the connection has actually met the anomaly.
            resolved: false,
            // Counts down after a rejection, so the mark lingers before clearing.
            hold: 0,
            fade: 1
        });

        if (runs.length > 40) {
            runs.shift();
        }
    }

    function drawFrame() {
        // The anomaly line, with a tick per lane.
        ctx.strokeStyle = LINE + '0.10)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, anomalyY);
        ctx.lineTo(width, anomalyY);
        ctx.stroke();

        ctx.font = '9px ui-monospace, SFMono-Regular, Menlo, monospace';
        ctx.textAlign = 'center';

        for (let i = 0; i < lanes.length; i += 1) {
            const x = lanes[i];

            ctx.strokeStyle = NEUTRAL + '0.05)';
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, height);
            ctx.stroke();

            ctx.strokeStyle = LINE + '0.18)';
            ctx.beginPath();
            ctx.moveTo(x, anomalyY - 4);
            ctx.lineTo(x, anomalyY + 4);
            ctx.stroke();

            ctx.fillStyle = NEUTRAL + '0.13)';
            ctx.fillText(String(FIRST_PORT + i), x, anomalyY - 11);
        }

        ctx.textAlign = 'left';
    }

    function drawRun(r) {
        const x = lanes[r.lane];
        if (x === undefined) {
            return;
        }

        // Before the line every connection looks the same. That is the point of
        // the suite: what a client is about to do is not visible in advance.
        if (!r.resolved) {
            ctx.fillStyle = NEUTRAL + (0.5 * r.fade) + ')';
            ctx.fillRect(x - 3, r.y - 3, 6, 6);
            return;
        }

        if (r.outcome === 'pass') {
            ctx.fillStyle = PASS + (0.55 * r.fade) + ')';
            ctx.fillRect(x - 3, r.y - 3, 6, 6);
            // A short wake, so a passing connection reads as still moving.
            ctx.fillStyle = PASS + (0.16 * r.fade) + ')';
            ctx.fillRect(x - 1, r.y - 16, 2, 12);
            return;
        }

        if (r.outcome === 'reject') {
            const a = 0.7 * r.fade;
            ctx.strokeStyle = REJECT + a + ')';
            ctx.lineWidth = 1.4;
            ctx.beginPath();
            ctx.moveTo(x - 4, r.y - 4);
            ctx.lineTo(x + 4, r.y + 4);
            ctx.moveTo(x + 4, r.y - 4);
            ctx.lineTo(x - 4, r.y + 4);
            ctx.stroke();
            return;
        }

        // Inconclusive: an outline that never fills in.
        ctx.strokeStyle = NEUTRAL + (0.5 * r.fade) + ')';
        ctx.lineWidth = 1;
        ctx.strokeRect(x - 3.5, r.y - 3.5, 7, 7);
    }

    function step(dt) {
        ctx.clearRect(0, 0, width, height);
        drawFrame();

        for (const r of runs) {
            if (!r.resolved) {
                r.y += r.speed * dt;
                if (r.y >= anomalyY) {
                    r.y = anomalyY;
                    r.resolved = true;
                    r.hold = r.outcome === 'pass' ? 0 : 900;
                }
            } else if (r.outcome === 'pass') {
                r.y += r.speed * dt;
                if (r.y > height + 20) {
                    r.fade = 0;
                }
            } else {
                // Rejections and inconclusives stop at the line and dissolve
                // there, which is where the result was decided.
                r.hold -= dt;
                if (r.hold <= 0) {
                    r.fade -= dt / 700;
                }
            }

            if (r.fade > 0) {
                drawRun(r);
            }
        }

        runs = runs.filter(function (r) {
            return r.fade > 0;
        });
    }

    function frame(now) {
        if (!running) {
            return;
        }
        if (!last) {
            last = now;
        }
        // Clamped so a backgrounded tab does not resume with one enormous step
        // that teleports every connection past the line it was meant to meet.
        const dt = Math.min(now - last, 50);
        last = now;

        if (now - lastSpawn > 260) {
            spawn();
            lastSpawn = now;
        }

        step(dt);
        rafId = window.requestAnimationFrame(frame);
    }

    function start() {
        running = true;
        last = 0;
        lastSpawn = 0;
        rafId = window.requestAnimationFrame(frame);
    }

    function stop() {
        running = false;
        if (rafId !== null) {
            window.cancelAnimationFrame(rafId);
            rafId = null;
        }
        ctx.clearRect(0, 0, width, height);
        drawFrame();
    }

    const toggle = document.createElement('button');
    toggle.className = 'cf-motion-toggle';
    toggle.type = 'button';

    function syncToggle() {
        toggle.textContent = running ? 'Pause motion' : 'Resume motion';
        toggle.setAttribute('aria-pressed', running ? 'false' : 'true');
    }

    toggle.addEventListener('click', function () {
        if (running) {
            stop();
        } else {
            start();
        }
        syncToggle();
        try {
            window.localStorage.setItem(STORAGE_KEY, running ? 'on' : 'off');
        } catch (e) {
            // Site data blocked. The toggle still works, it just is not remembered.
        }
    });

    window.addEventListener('resize', resize);

    resize();
    document.body.appendChild(toggle);

    let stored = null;
    try {
        stored = window.localStorage.getItem(STORAGE_KEY);
    } catch (e) {
        stored = null;
    }

    if (stored === 'off') {
        running = false;
        drawFrame();
        syncToggle();
    } else {
        start();
        syncToggle();
    }
}());
