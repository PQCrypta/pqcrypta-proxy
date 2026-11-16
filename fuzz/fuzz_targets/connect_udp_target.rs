//! A CONNECT-UDP request target (RFC 9298).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::connect_udp_target(data));
