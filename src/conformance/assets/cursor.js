/**
 * Conformance cursor: your session, trailing the results it has collected.
 *
 * The head is the test currently running. Behind it are recorded verdicts, in
 * the five class colours the report uses, with the occasional inconclusive drawn
 * as an outline that never fills — which is how the suite reports a run that
 * never put the client in the situation the test was about.
 *
 * Skipped on coarse pointers, where there is no cursor to replace.
 */
(function () {
    'use strict';

    if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) {
        return;
    }

    const TRAIL = 9;
    // Report order, with inconclusive appearing about as often as it does in a
    // real run against a client that cannot reach every test.
    const CLASSES = [
        'cf-cursor-ext',
        'cf-cursor-corr',
        'cf-cursor-inter',
        'cf-cursor-resil',
        'cf-cursor-disc',
        'cf-cursor-incon'
    ];

    const head = document.createElement('div');
    head.className = 'cf-cursor';
    document.body.appendChild(head);

    // Only now hide the native pointer. The stylesheet does nothing until this
    // class is set, so if this script had failed to load the real cursor would
    // still be there — hiding it from CSS would have left a page with no pointer
    // at all whenever the replacement did not arrive.
    document.body.classList.add('cf-cursor-on');

    const trail = [];
    for (let i = 0; i < TRAIL; i += 1) {
        const el = document.createElement('div');
        el.className = 'cf-cursor-trail ' + CLASSES[i % CLASSES.length];
        document.body.appendChild(el);
        trail.push({ el: el, x: 0, y: 0 });
    }

    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let headX = mouseX;
    let headY = mouseY;

    document.addEventListener('mousemove', function (e) {
        mouseX = e.clientX;
        mouseY = e.clientY;
    }, { passive: true });

    document.addEventListener('mouseover', function (e) {
        const t = e.target;
        if (t instanceof Element && t.closest('a, button, summary, code')) {
            head.classList.add('cf-cursor-active');
        }
    }, { passive: true });

    document.addEventListener('mouseout', function (e) {
        const t = e.target;
        if (t instanceof Element && t.closest('a, button, summary, code')) {
            head.classList.remove('cf-cursor-active');
        }
    }, { passive: true });

    function tick() {
        headX += (mouseX - headX) * 0.24;
        headY += (mouseY - headY) * 0.24;
        head.style.transform = 'translate(' + headX + 'px, ' + headY + 'px)';

        let px = headX;
        let py = headY;

        for (let i = 0; i < trail.length; i += 1) {
            const seg = trail[i];
            seg.x += (px - seg.x) * 0.32;
            seg.y += (py - seg.y) * 0.32;
            seg.el.style.transform = 'translate(' + seg.x + 'px, ' + seg.y + 'px)';
            seg.el.style.opacity = String(0.55 * (1 - i / trail.length));
            px = seg.x;
            py = seg.y;
        }

        window.requestAnimationFrame(tick);
    }

    window.requestAnimationFrame(tick);
}());
