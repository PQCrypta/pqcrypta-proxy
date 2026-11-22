// The interstitial's script: hands the challenge to a worker and, with the
// number it finds, asks the proxy for a pass (see src/challenge.rs).
'use strict';

const PREFIX = '/.well-known/pqcrypta-challenge/';

function base64url(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function start() {
    const root = document.getElementById('pqc-challenge');
    const status = document.getElementById('pqc-status');
    if (!root || !status) return;
    let challenge;
    try {
        challenge = JSON.parse(root.dataset.challenge);
    } catch {
        status.textContent = 'The check could not start. Reload the page to try again.';
        return;
    }
    // The interstitial stands at the address asked for: return there
    const back = location.pathname + location.search;
    const began = performance.now();
    const worker = new Worker(PREFIX + 'worker.js');
    worker.addEventListener('message', (event) => {
        const { number, progress } = event.data;
        if (progress !== undefined) {
            status.textContent = `Working… ${Math.min(99, Math.round(progress * 100))}%`;
            return;
        }
        worker.terminate();
        if (number === null) {
            status.textContent = 'The check did not finish. Reload the page to try again.';
            return;
        }
        const seconds = ((performance.now() - began) / 1000).toFixed(1);
        status.textContent = `Done in ${seconds} s. Continuing…`;
        const solution = {
            algorithm: challenge.algorithm,
            challenge: challenge.challenge,
            number,
            salt: challenge.salt,
            signature: challenge.signature,
        };
        const query = new URLSearchParams({ solution: base64url(JSON.stringify(solution)), return: back });
        location.replace(PREFIX + 'pass?' + query.toString());
    });
    worker.addEventListener('error', () => {
        status.textContent = 'The check could not run in this browser. Reload the page to try again.';
    });
    worker.postMessage(challenge);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
} else {
    start();
}
