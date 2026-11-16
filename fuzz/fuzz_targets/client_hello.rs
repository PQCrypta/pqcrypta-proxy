//! A TLS record carrying a ClientHello: the extension readers, the two SNI readers (which must agree), JA3/JA4.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::client_hello(data));
