//! Mutation fuzzing for the parsers that read raw client bytes.
//!
//! Release builds use `panic = "abort"`, so a panic anywhere a client's bytes
//! are parsed ends the whole process on every node. Two such panics were in the
//! ClientHello fingerprinter (a9949b0, 310fb2e); these tests exist so the next
//! one is found here.
//!
//! Deterministic (xorshift64*), so a failure reproduces. `PQ_FUZZ_SEED` and
//! `PQ_FUZZ_ITERS` run another or a longer campaign; a failure names the seed,
//! the iteration and the exact input in hex.

/// Mutate `seed_input` `default_iterations` times (or `PQ_FUZZ_ITERS`) and run
/// `check` on every mutant; fails with a replayable report if `check` panics.
pub(crate) fn fuzz_bytes(seed_input: &[u8], default_iterations: u64, check: impl Fn(&[u8])) {
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let seed = env("PQ_FUZZ_SEED").unwrap_or(0x9e37_79b9_7f4a_7c15) | 1;
    let iterations = env("PQ_FUZZ_ITERS").unwrap_or(default_iterations);
    let mut state = seed;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    // The generator's low bytes, and a value below `bound`.
    let byte = |r: u64| r.to_le_bytes()[0];
    let below = |r: u64, bound: usize| usize::try_from(r % bound as u64).unwrap_or(0);
    let multibyte: [&[u8]; 4] = [
        "€".as_bytes(),
        "é".as_bytes(),
        "😀".as_bytes(),
        &[0xff, 0xfe],
    ];

    for iteration in 0..iterations {
        let mut m = seed_input.to_vec();
        for _ in 0..=(next() % 4) {
            if m.is_empty() {
                m.push(byte(next()));
                continue;
            }
            let at = below(next(), m.len());
            match next() % 6 {
                0 => m[at] ^= 1 << (next() % 8),
                1 => m[at] = byte(next()),
                2 => m.truncate(at.max(1)),
                3 => {
                    let splice = multibyte[below(next(), multibyte.len())];
                    m.splice(at..at, splice.iter().copied());
                }
                4 => {
                    // rewrite a two-byte length field with an arbitrary value
                    if at + 1 < m.len() {
                        let v = next().to_le_bytes();
                        m[at] = v[0];
                        m[at + 1] = v[1];
                    }
                }
                _ => {
                    // repeat a stretch, as a duplicated field or extension would
                    let len = below(next(), 16).min(m.len() - at);
                    let chunk = m[at..at + len].to_vec();
                    m.splice(at..at, chunk);
                }
            }
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&m)));
        assert!(
            outcome.is_ok(),
            "panicked at seed {seed:#x}, iteration {iteration}, input {}",
            hex::encode(&m)
        );
    }
}
