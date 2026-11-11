# Changelog

## [0.6.0](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.5.0...v0.6.0) (2026-11-11)


### Features

* pentest_bypass_ips takes host names, resolved through a validating resolver ([ff960dd](https://github.com/PQCrypta/pqcrypta-proxy/commit/ff960dda0c263e9bfce8658b428c4840c874bc7c))
* **quic:** QUIC stack on upstream noq main, wtransport 0.7.2+, axum 0.8, toml 1.2 ([e10b9a8](https://github.com/PQCrypta/pqcrypta-proxy/commit/e10b9a8adf19a856d6116cfbd42be9cdea7667da))
* **quic:** QUIC stack on upstream noq main, wtransport 0.7.2+, axum 0.8, toml 1.2, x509-parser 0.18 ([21f64e7](https://github.com/PQCrypta/pqcrypta-proxy/commit/21f64e7efb7e30406fa59a86029a8fb84a187192))
* **speedtest:** the session's QUIC counters as the server sees them ([06a556c](https://github.com/PQCrypta/pqcrypta-proxy/commit/06a556c362db73a104513e123e5f4aa75dbdb621))


### Bug Fixes

* a rejected WebTransport request ends both halves; the oversized field section test sizes past the client's own limit ([ead6283](https://github.com/PQCrypta/pqcrypta-proxy/commit/ead628367f00b30b3f87901167176e06cbe61854))
* a rejected WebTransport request ends both halves; the oversized field section test sizes past the client's own limit ([62e7d0f](https://github.com/PQCrypta/pqcrypta-proxy/commit/62e7d0f3a30e2b36a83adceb6407dd980ae617f6))
* clippy on all targets -- the held-body check as if let, the dynamic-table harness asserts its answer, a test's redundant clone ([810f263](https://github.com/PQCrypta/pqcrypta-proxy/commit/810f263960863239d42e8beb8736145c891be450))
* **conformance, h3-get:** an unseen retry keeps the close that was seen; h3-get lets its refusal reach the server ([c4588b1](https://github.com/PQCrypta/pqcrypta-proxy/commit/c4588b1c7b3ee71329b7f3e8d2c295fef2a484a4))
* **conformance:** a connection the probe could not reach does not replace one whose ending was seen ([f5c1fb0](https://github.com/PQCrypta/pqcrypta-proxy/commit/f5c1fb076d26f1fe4c16958efd3d052ea19cea65))
* **conformance:** a stopped request stream is the refusal the oversized section test asks for ([c57fa98](https://github.com/PQCrypta/pqcrypta-proxy/commit/c57fa98ead6e4fa84bd8518874c53959f27163e4))
* **conformance:** a stopped request stream is the refusal the oversized section test asks for ([57d961f](https://github.com/PQCrypta/pqcrypta-proxy/commit/57d961fe8eb3e2dc69b85a310f83cc22ea19a88c))
* **conformance:** abandon the stateless-reset connection once the client has caught up, not mid-burst ([0719bf7](https://github.com/PQCrypta/pqcrypta-proxy/commit/0719bf70401e5fa9f5fef148c1f4716a32390b58))
* **conformance:** silence after an oversized section is inconclusive, not "decoded it" ([8a437b5](https://github.com/PQCrypta/pqcrypta-proxy/commit/8a437b5201b10b2685fe2d6b76261eb5e4294ed0))
* **conformance:** silence after an oversized section is inconclusive, not "decoded it" ([bd7e63f](https://github.com/PQCrypta/pqcrypta-proxy/commit/bd7e63f979a1e88c42f43cb56c60fd5241589ccd))
* **conformance:** the oversized section test holds the body back, so a refusal has a stream to stop ([2deeb17](https://github.com/PQCrypta/pqcrypta-proxy/commit/2deeb178656ea2d5ec0e222c2c2556797335795a))
* **conformance:** the oversized section test holds the body back, so a refusal has a stream to stop ([dd8007a](https://github.com/PQCrypta/pqcrypta-proxy/commit/dd8007a5398a96edf2b2b0bc4a326088600bb5ea))
* **conformance:** the oversized section test reaches quic-go's 10 MiB limit ([9e2e4ae](https://github.com/PQCrypta/pqcrypta-proxy/commit/9e2e4aea3505154421162b05ee4b8be6ff7789d8))
* **conformance:** the oversized section test reaches quic-go's 10 MiB limit ([d0f8d8c](https://github.com/PQCrypta/pqcrypta-proxy/commit/d0f8d8c0cb4e4cc2df4e23a10334d0daca6881d0))
* **conformance:** the oversized section test reads 2^62-1 as no limit, and says why a connection close fails ([e2a39bc](https://github.com/PQCrypta/pqcrypta-proxy/commit/e2a39bc0d4243e2ffb64ef31b2c97a762fe5adaa))
* **conformance:** the oversized section test reads 2^62-1 as no limit, and says why a connection close fails ([5287d6b](https://github.com/PQCrypta/pqcrypta-proxy/commit/5287d6bd952ff282825cfd450d8b8d49ba8bec0b))
* **conformance:** the Stateless Reset test probes with a PATH_CHALLENGE, so silence after the reset means recognition ([10cb3cd](https://github.com/PQCrypta/pqcrypta-proxy/commit/10cb3cd2c73a0a3e2de3ff0e13fecf0cc2c051b9))
* **conformance:** the Stateless Reset test proves recognition, and stops flooding the client before it ([e631e23](https://github.com/PQCrypta/pqcrypta-proxy/commit/e631e235fd68860302df6e80e8b70c3fb766a0cd))
* **deps:** one version of every crate cargo-deny bans, and its skips match the graph ([102d1bc](https://github.com/PQCrypta/pqcrypta-proxy/commit/102d1bcd3f08cff0bc72a7369067c6e47124e01e))
* **deps:** the OpenSSL license stays allowed: aws-lc-fips-sys under the fips feature ([953b1ef](https://github.com/PQCrypta/pqcrypta-proxy/commit/953b1ef581e8fa224744cab95c31c8b1b26bdfc8))
* **h3-get:** let a refusal reach the server before the connection closes; noq gains Connection::is_settled ([261cb4c](https://github.com/PQCrypta/pqcrypta-proxy/commit/261cb4c3fa614035f1222cc896d42d4d43e29f4e))
* **h3-get:** settle's bound reads the first path's RTT, as noq's multipath API has it ([5beb60b](https://github.com/PQCrypta/pqcrypta-proxy/commit/5beb60be83e19545a641cd77b43c64851cea4203))
* **h3:** bound field sections and buffered frames; no HeaderMap panic (QPACK header accordions) ([8b184ce](https://github.com/PQCrypta/pqcrypta-proxy/commit/8b184ce4b46bbbe4a2d1d1fd44bd7cf7cd0160d2))
* **h3:** bound field sections and buffered frames; no HeaderMap panic (QPACK header accordions) ([5fcae48](https://github.com/PQCrypta/pqcrypta-proxy/commit/5fcae48b423e0b702606270c71b3fe41436cbd27))
* **quic:** BBRv3 knows when the sender ran dry, so a flow of small packets is not taken for the path's bandwidth ([70fb25a](https://github.com/PQCrypta/pqcrypta-proxy/commit/70fb25a2af5f0c236aa63f619f6e5309a8b5c124))
* **quic:** BBRv3 paces the connection at its own rate (noq [#785](https://github.com/PQCrypta/pqcrypta-proxy/issues/785)) ([d86cf4d](https://github.com/PQCrypta/pqcrypta-proxy/commit/d86cf4d3ad9b316614e580a1dc268a59440f59eb))
* **speedtest:** route analysis in under 3 s; the path MTU from QUIC's own discovery ([8f650b5](https://github.com/PQCrypta/pqcrypta-proxy/commit/8f650b54d9e8c3e5ac104eb75322684a5adc0c42))
* the regression gate holds the tester to the API's whitelist too, over both address families ([8ebad51](https://github.com/PQCrypta/pqcrypta-proxy/commit/8ebad51db61d01b9c06c7907ddaa7d52fb1f3f1b))
* **wtransport:** drop StreamBiRemoteH3::stop, unused since reject(); the fork's CI job fails on warnings ([8a9016c](https://github.com/PQCrypta/pqcrypta-proxy/commit/8a9016ccaf843f3b58832bf2f07227a14b01c9fd))
* **wtransport:** drop StreamBiRemoteH3::stop, unused since reject(); the fork's CI job fails on warnings ([906b41f](https://github.com/PQCrypta/pqcrypta-proxy/commit/906b41f03f089c8efe49318947c327144cbf98f0))

## [0.5.0](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.4.1...v0.5.0) (2026-11-03)


### Features

* **acme:** certificates for IP addresses, renewal by ARI, CT logs from the log list ([481c7d0](https://github.com/PQCrypta/pqcrypta-proxy/commit/481c7d0bcd6cc90a2c65b1acc525204d1eba79bb))
* **acme:** certificates for IP addresses, renewal by ARI, CT logs from the log list ([38ac27c](https://github.com/PQCrypta/pqcrypta-proxy/commit/38ac27c6c3e8fc97d15319160614e207b1273b2e))
* **acme:** dns-01 and dns-account-01 by TSIG-signed DNS UPDATE ([8566013](https://github.com/PQCrypta/pqcrypta-proxy/commit/8566013c656bf1b45b817fa0b46063b81ed1ae1e))
* **acme:** dns-01 and dns-account-01 by TSIG-signed DNS UPDATE ([79015cd](https://github.com/PQCrypta/pqcrypta-proxy/commit/79015cd60307c967c8d5d19046506d9e68681b31))


### Bug Fixes

* **deps:** crypto-bigint 0.7.6 (RUSTSEC-2026-0387), inout 0.2.5 (0.2.3 yanked) ([20b3474](https://github.com/PQCrypta/pqcrypta-proxy/commit/20b3474e6ac944222a5e397ec30354060ff51cd1))
* **h3:** the GREASE frame goes ahead of the response, not last on the stream ([def5204](https://github.com/PQCrypta/pqcrypta-proxy/commit/def52043274385a77ce55e293f5004b377b7d398))
* **h3:** the GREASE frame goes ahead of the response, not last on the stream ([8e7fa4c](https://github.com/PQCrypta/pqcrypta-proxy/commit/8e7fa4c377b9101bb842073f1f2b57653cb85199))
* name_end is a test-only import in doh.rs (release builds deny unused imports) ([cba161e](https://github.com/PQCrypta/pqcrypta-proxy/commit/cba161e4f617bcbde75681a9dd6b432e43517eba))
* **tls:** an address sent as the server name gets the certificate naming the address ([3b998ea](https://github.com/PQCrypta/pqcrypta-proxy/commit/3b998ea7fdbeb32dd3cb2768d6c7bd40c10fcee8))
* **tls:** an address sent as the server name gets the certificate naming the address ([20fc4e6](https://github.com/PQCrypta/pqcrypta-proxy/commit/20fc4e6f40d58ecf613c2fe1a4fd3de0ca846646))

## [0.4.1](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.4.0...v0.4.1) (2026-10-23)


### Bug Fixes

* **deps:** ctutils 0.4.5 (RUSTSEC-2026-0385) ([2ce9390](https://github.com/PQCrypta/pqcrypta-proxy/commit/2ce9390af697074d535d7d5a68819f0594b7bfc3))

## [0.4.0](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.3.0...v0.4.0) (2026-10-23)


### Features

* **doh:** DNS over HTTPS gateway for a name server on this host ([a5fb93b](https://github.com/PQCrypta/pqcrypta-proxy/commit/a5fb93bcb9c2ecdbf858d9f172127b4efbec4904))


### Bug Fixes

* **routing:** IPv6 literal hosts get their route's policy ([912285c](https://github.com/PQCrypta/pqcrypta-proxy/commit/912285c548d0dba671ae4be94ffa8c8c70f0ac1c))
* **routing:** match a bracketed IPv6 host with a port over TCP ([99d2fa6](https://github.com/PQCrypta/pqcrypta-proxy/commit/99d2fa6b648fe520ca58147d85cfb751bdb64217))
* **tls:** answer a ClientHello with no server name with the primary certificate ([aa9a475](https://github.com/PQCrypta/pqcrypta-proxy/commit/aa9a4751f7a5087e96d3affecbe8d7cc4d54c0eb))

## [0.3.0](https://github.com/PQCrypta/pqcrypta-proxy/compare/v0.2.2...v0.3.0) (2026-10-19)


### Features

* **acme:** migrate instant-acme 0.7 -&gt; 0.8 ([2f5d1c8](https://github.com/PQCrypta/pqcrypta-proxy/commit/2f5d1c8a275c249fec31f5838e8be7d8b6efd903))
* **admin:** cache purge, and one cache instead of five ([f2fb376](https://github.com/PQCrypta/pqcrypta-proxy/commit/f2fb37648c61bf8c6d5aff3dbb384271a80725bc))
* **bot-detect:** honeypot edge feed + bot_ip_tracking replay ([526d962](https://github.com/PQCrypta/pqcrypta-proxy/commit/526d96204cbc0fbc3efe859923001b543a60c9d7))
* **config:** make enable_signatures, worker_threads, enable_ipv6, ([7751f1a](https://github.com/PQCrypta/pqcrypta-proxy/commit/7751f1a4636e850aa62638085db1874d87f6f138))
* **conformance:** 27 live listeners, and four verdict bugs found by running them ([fd99671](https://github.com/PQCrypta/pqcrypta-proxy/commit/fd99671558412cd23a6533e1ca4f719cb5397121))
* **conformance:** all 14 HTTP/3 anomalies, and three more of my own bugs ([15fd66c](https://github.com/PQCrypta/pqcrypta-proxy/commit/15fd66cc6e77624aae74128a0b208aeebb9da815))
* **conformance:** catalogue, verdicts and frame writer for the client suite ([4c8044c](https://github.com/PQCrypta/pqcrypta-proxy/commit/4c8044cb644e213cbb66bcef3146062a616f0b64))
* **conformance:** h3-conformance, a CI driver that drives your client ([cff4104](https://github.com/PQCrypta/pqcrypta-proxy/commit/cff41046b6d9bb26207178123a276385d663433e))
* **conformance:** reports, sessions that actually correlate, and a fifth verdict class ([a5808fc](https://github.com/PQCrypta/pqcrypta-proxy/commit/a5808fc8539c9398b05514fe636190cf7f92bc73))
* **conformance:** six QUIC-layer tests, and an honest outcome for tests that did not run ([722a875](https://github.com/PQCrypta/pqcrypta-proxy/commit/722a87547e35a2df309137de3c19958460b9297c))
* **early-hints:** exact-path matching for per-page 103 preloads ([1551e11](https://github.com/PQCrypta/pqcrypta-proxy/commit/1551e1115db6939038ccb22727b16ffcbb417216))
* **fingerprints:** distribute the GeoIP databases with the JA3 database ([a8d0978](https://github.com/PQCrypta/pqcrypta-proxy/commit/a8d0978ade7d340f1240e3069bf21ff0ca99b259))
* **geoip:** refresh the GeoLite2 masters, and sync to the path each node reads ([a951324](https://github.com/PQCrypta/pqcrypta-proxy/commit/a951324ecc32500853a5b1418fe6f473254985e9))
* **limits:** enforce connection rate, pool caps and connect timeout ([0a57aa8](https://github.com/PQCrypta/pqcrypta-proxy/commit/0a57aa838816edbf8e0104a2a4e7744f0c691b08))
* **logging:** make [logging] file real, with size-based rotation ([1a3d239](https://github.com/PQCrypta/pqcrypta-proxy/commit/1a3d2398948b01f2ee16808868d2ffb0f9f29673))
* **quic:** full multipath via noq, server-side ECH, configurable Retry ([d75c6f4](https://github.com/PQCrypta/pqcrypta-proxy/commit/d75c6f4f4422acb3b2d697c503bb69b6f8538be8))
* **quic:** implement QUIC v2 (RFC 9369) in the noq fork, advertise v1+v2 ([08aed32](https://github.com/PQCrypta/pqcrypta-proxy/commit/08aed3214b06b54c82e2880a50e30a7ec081303c))
* **quic:** make the multipath path budget configurable ([42cbe73](https://github.com/PQCrypta/pqcrypta-proxy/commit/42cbe73d001f1636af202c16858fe62c700ebecf))
* **routes:** apply remove_headers, and make the body-size override real ([3e93012](https://github.com/PQCrypta/pqcrypta-proxy/commit/3e93012d72e232f31f8a9ba8851d51196e7f526f))
* **security:** fingerprint QUIC clients, expose ECH, share security state ([5191ce9](https://github.com/PQCrypta/pqcrypta-proxy/commit/5191ce91ff354deb375b124d9f5b4efd8d1cf3ba))
* **security:** resolve per-route policy before the security checks run ([21a321a](https://github.com/PQCrypta/pqcrypta-proxy/commit/21a321a3e08244be0e36f013d37b241bac176fad))
* **startup:** probe the bound listener, and emit the attestation as fields ([eee6262](https://github.com/PQCrypta/pqcrypta-proxy/commit/eee6262977389150096c3656a18d66a24a478e31))
* **startup:** probe WAF, rate limiting and mTLS enforcement ([b0fa941](https://github.com/PQCrypta/pqcrypta-proxy/commit/b0fa941694b02f70170a7fd6666eb2e84d165eaf))
* **startup:** verify the cryptographic runtime instead of describing it ([2101c24](https://github.com/PQCrypta/pqcrypta-proxy/commit/2101c2484b84c4f4a0d9066e4b7426ed1259b1d2))
* **tls:** real ML-KEM-1024 session tickets ([dad03ba](https://github.com/PQCrypta/pqcrypta-proxy/commit/dad03ba118071a60e35458b9c8a80035f0e7ebd9))
* **tls:** serve ML-DSA-87 (FIPS 204) server certificates per SNI ([0a525f9](https://github.com/PQCrypta/pqcrypta-proxy/commit/0a525f947226e644b4cb6623b67529f88cc699b5))
* **webtransport:** advertise v1+v2 on the WebTransport endpoint ([2a77339](https://github.com/PQCrypta/pqcrypta-proxy/commit/2a77339ea76e7c0921d84b6f894d3ad56e9c7ad7))


### Bug Fixes

* **cache:** bypass response cache for Range requests on h1/h2 path ([7af88f7](https://github.com/PQCrypta/pqcrypta-proxy/commit/7af88f7d0fd2b26d2baeb8f21304e42f49def1fa))
* **cache:** never store a response carrying a CSP nonce ([1ba6205](https://github.com/PQCrypta/pqcrypta-proxy/commit/1ba620519c5f0cfa736693884cd2a1be7c1cbe30))
* **config:** make every PQC and timeout flag do what it says ([2f92ba5](https://github.com/PQCrypta/pqcrypta-proxy/commit/2f92ba5e2810f9571199f5ff48a008c9a9287545))
* **conformance:** verify every expected_code against the published RFC text ([ac6f197](https://github.com/PQCrypta/pqcrypta-proxy/commit/ac6f1970bed3ed983204b198c9919ad2b5ddc465))
* **conformance:** verify the seven unbuilt QUIC tests, and record how each was checked ([f6f73d8](https://github.com/PQCrypta/pqcrypta-proxy/commit/f6f73d86786fc801763b0f76a2e5d12c905b6a03))
* **deny:** restore itertools/redox_syscall skips (needed under CI --all-features) ([496909c](https://github.com/PQCrypta/pqcrypta-proxy/commit/496909cb8ccf34f44d3d56c991c21a551b39bb7c))
* **deps:** update crossbeam-epoch 0.9.18 -&gt; 0.9.20 (RUSTSEC-2026-0204) ([f154273](https://github.com/PQCrypta/pqcrypta-proxy/commit/f1542734145f826b9160436cd7e4955afadb5fb3))
* **fingerprints:** stop the weekly refresh from deleting curated JA3 entries ([ebf95cb](https://github.com/PQCrypta/pqcrypta-proxy/commit/ebf95cb6f81ca3525fa6113b905c216fe6bbc9a8))
* **fingerprint:** the JA3 database now decides something ([205f507](https://github.com/PQCrypta/pqcrypta-proxy/commit/205f50795c79de5d319712b6d1afdb03bcbdea1b))
* **geoip:** anchor the placeholder-credential check to the directives ([fb3f50b](https://github.com/PQCrypta/pqcrypta-proxy/commit/fb3f50b3fd4c50cd673f8bcc3f5cc06521d53e31))
* **head:** stop synthesizing content-length: 0 on HEAD responses ([0392cee](https://github.com/PQCrypta/pqcrypta-proxy/commit/0392cee1772addc82624e4e396be1b9ae060259d))
* **logging,waf:** stop benign h3 closes logging as errors; honour pentest bypass ([370d500](https://github.com/PQCrypta/pqcrypta-proxy/commit/370d500ef6331238c5742dd4477d93ba06fef12e))
* **logging:** make [logging] level and format actually control logging ([6cc1933](https://github.com/PQCrypta/pqcrypta-proxy/commit/6cc19336295c348ad9d69b86ef6e791690aa242f))
* **net:** canonicalize IPv4-mapped peer addresses at accept boundary ([ee72eb7](https://github.com/PQCrypta/pqcrypta-proxy/commit/ee72eb7714d4f58ef9421abdf8dc12ec598feb55))
* **ocsp:** stop warning hourly about certificates with no responder ([3f085ce](https://github.com/PQCrypta/pqcrypta-proxy/commit/3f085ce465f06ce1cdf7383ce1407b17c39ce7d6))
* **security:** enforce WAF on the HTTP/3 path ([e75d469](https://github.com/PQCrypta/pqcrypta-proxy/commit/e75d469b7fcb35b9e6b2a8755e0bc6bf91060f3b))
* **security:** reconcile the synced blocklist so unblocks actually take effect ([4411b32](https://github.com/PQCrypta/pqcrypta-proxy/commit/4411b32bc1a800b89388be7d824b24f4756527a8))
* **startup:** share the live SecurityState, and probe both rate limiters ([35ce06e](https://github.com/PQCrypta/pqcrypta-proxy/commit/35ce06e73914764f0bda154af77fe1d290d3b435))
* **tls:** gate ML-DSA certificate support out of fips builds ([0fbee2d](https://github.com/PQCrypta/pqcrypta-proxy/commit/0fbee2d4e4a603340383b10dc2a0e023823aee86))
* **waf:** exempt public download endpoints from scanner-UA block; enforce backend request timeout ([e4bfb3e](https://github.com/PQCrypta/pqcrypta-proxy/commit/e4bfb3eca5f83f290e4e60101ea6e89c137c4e7a))
* **waf:** stop truncating request bodies over 64KB during body scanning ([a38752a](https://github.com/PQCrypta/pqcrypta-proxy/commit/a38752a90eb0d43c3dbfb98534fb49ea967d6ddb))
