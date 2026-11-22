// Finds the n in 0..=maxnumber for which SHA-256(salt + n) is the challenge
// (ALTCHA's proof of work), with Web Crypto, many digests in flight at once.
'use strict';

const BATCH = 1000;

function fromHex(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function equal(buffer, target) {
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < target.length; i++) if (bytes[i] !== target[i]) return false;
    return true;
}

self.addEventListener('message', async (event) => {
    const { salt, challenge, maxnumber } = event.data;
    const target = fromHex(String(challenge).toLowerCase());
    const encoder = new TextEncoder();
    let reported = 0;
    for (let start = 0; start <= maxnumber; start += BATCH) {
        const end = Math.min(start + BATCH - 1, maxnumber);
        const digests = [];
        for (let n = start; n <= end; n++) {
            digests.push(crypto.subtle.digest('SHA-256', encoder.encode(salt + n)));
        }
        const done = await Promise.all(digests);
        for (let i = 0; i < done.length; i++) {
            if (equal(done[i], target)) {
                self.postMessage({ number: start + i });
                return;
            }
        }
        // Progress against the expected work (half the range), at most every 5%
        const progress = (end + 1) / (maxnumber / 2 + 1);
        if (progress - reported >= 0.05) {
            reported = progress;
            self.postMessage({ progress: Math.min(progress, 0.99) });
        }
    }
    self.postMessage({ number: null });
});
