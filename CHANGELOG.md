# Changelog

## [0.3.0](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.2.2...v0.3.0) (2026-08-01)


### Features

* **acme:** migrate instant-acme 0.7 -&gt; 0.8 ([2f5d1c8](https://github.com/PQCrypta/pqcrypta-proxy/commit/2f5d1c8a275c249fec31f5838e8be7d8b6efd903))
* **bot-detect:** honeypot edge feed + bot_ip_tracking replay ([526d962](https://github.com/PQCrypta/pqcrypta-proxy/commit/526d96204cbc0fbc3efe859923001b543a60c9d7))
* **config:** make enable_signatures, worker_threads, enable_ipv6, ([7751f1a](https://github.com/PQCrypta/pqcrypta-proxy/commit/7751f1a4636e850aa62638085db1874d87f6f138))
* **early-hints:** exact-path matching for per-page 103 preloads ([1551e11](https://github.com/PQCrypta/pqcrypta-proxy/commit/1551e1115db6939038ccb22727b16ffcbb417216))
* **limits:** enforce connection rate, pool caps and connect timeout ([0a57aa8](https://github.com/PQCrypta/pqcrypta-proxy/commit/0a57aa838816edbf8e0104a2a4e7744f0c691b08))
* **quic:** full multipath via noq, server-side ECH, configurable Retry ([d75c6f4](https://github.com/PQCrypta/pqcrypta-proxy/commit/d75c6f4f4422acb3b2d697c503bb69b6f8538be8))
* **quic:** implement QUIC v2 (RFC 9369) in the noq fork, advertise v1+v2 ([08aed32](https://github.com/PQCrypta/pqcrypta-proxy/commit/08aed3214b06b54c82e2880a50e30a7ec081303c))
* **quic:** make the multipath path budget configurable ([42cbe73](https://github.com/PQCrypta/pqcrypta-proxy/commit/42cbe73d001f1636af202c16858fe62c700ebecf))
* **routes:** apply remove_headers, and make the body-size override real ([3e93012](https://github.com/PQCrypta/pqcrypta-proxy/commit/3e93012d72e232f31f8a9ba8851d51196e7f526f))
* **security:** resolve per-route policy before the security checks run ([21a321a](https://github.com/PQCrypta/pqcrypta-proxy/commit/21a321a3e08244be0e36f013d37b241bac176fad))
* **tls:** real ML-KEM-1024 session tickets ([dad03ba](https://github.com/PQCrypta/pqcrypta-proxy/commit/dad03ba118071a60e35458b9c8a80035f0e7ebd9))
* **tls:** serve ML-DSA-87 (FIPS 204) server certificates per SNI ([0a525f9](https://github.com/PQCrypta/pqcrypta-proxy/commit/0a525f947226e644b4cb6623b67529f88cc699b5))
* **webtransport:** advertise v1+v2 on the WebTransport endpoint ([2a77339](https://github.com/PQCrypta/pqcrypta-proxy/commit/2a77339ea76e7c0921d84b6f894d3ad56e9c7ad7))


### Bug Fixes

* **cache:** bypass response cache for Range requests on h1/h2 path ([7af88f7](https://github.com/PQCrypta/pqcrypta-proxy/commit/7af88f7d0fd2b26d2baeb8f21304e42f49def1fa))
* **cache:** never store a response carrying a CSP nonce ([1ba6205](https://github.com/PQCrypta/pqcrypta-proxy/commit/1ba620519c5f0cfa736693884cd2a1be7c1cbe30))
* **config:** make every PQC and timeout flag do what it says ([2f92ba5](https://github.com/PQCrypta/pqcrypta-proxy/commit/2f92ba5e2810f9571199f5ff48a008c9a9287545))
* **deny:** restore itertools/redox_syscall skips (needed under CI --all-features) ([496909c](https://github.com/PQCrypta/pqcrypta-proxy/commit/496909cb8ccf34f44d3d56c991c21a551b39bb7c))
* **deps:** update crossbeam-epoch 0.9.18 -&gt; 0.9.20 (RUSTSEC-2026-0204) ([f154273](https://github.com/PQCrypta/pqcrypta-proxy/commit/f1542734145f826b9160436cd7e4955afadb5fb3))
* **fingerprint:** the JA3 database now decides something ([205f507](https://github.com/PQCrypta/pqcrypta-proxy/commit/205f50795c79de5d319712b6d1afdb03bcbdea1b))
* **logging,waf:** stop benign h3 closes logging as errors; honour pentest bypass ([370d500](https://github.com/PQCrypta/pqcrypta-proxy/commit/370d500ef6331238c5742dd4477d93ba06fef12e))
* **net:** canonicalize IPv4-mapped peer addresses at accept boundary ([ee72eb7](https://github.com/PQCrypta/pqcrypta-proxy/commit/ee72eb7714d4f58ef9421abdf8dc12ec598feb55))
* **ocsp:** stop warning hourly about certificates with no responder ([3f085ce](https://github.com/PQCrypta/pqcrypta-proxy/commit/3f085ce465f06ce1cdf7383ce1407b17c39ce7d6))
* **security:** enforce WAF on the HTTP/3 path ([e75d469](https://github.com/PQCrypta/pqcrypta-proxy/commit/e75d469b7fcb35b9e6b2a8755e0bc6bf91060f3b))
* **tls:** gate ML-DSA certificate support out of fips builds ([0fbee2d](https://github.com/PQCrypta/pqcrypta-proxy/commit/0fbee2d4e4a603340383b10dc2a0e023823aee86))
* **waf:** exempt public download endpoints from scanner-UA block; enforce backend request timeout ([e4bfb3e](https://github.com/PQCrypta/pqcrypta-proxy/commit/e4bfb3eca5f83f290e4e60101ea6e89c137c4e7a))
* **waf:** stop truncating request bodies over 64KB during body scanning ([a38752a](https://github.com/PQCrypta/pqcrypta-proxy/commit/a38752a90eb0d43c3dbfb98534fb49ea967d6ddb))
