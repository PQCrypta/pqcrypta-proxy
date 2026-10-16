# pqcrypta-hpke-pq (vendored)

Canonical source: `public/ent/hpke-pq/` in pqcrypta-platform, where the
discovery agent uses the same suites to test a published ECH config. Copied
here verbatim so the proxy builds without that repository; change it there and
copy it back, or the two will open and seal with different code.

Here it resolves `rustls` to `vendor/rustls-fixed` through `[patch.crates-io]`;
the `Hpke` trait is identical to upstream 0.23.46's.
