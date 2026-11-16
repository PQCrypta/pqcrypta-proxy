//! A DNS message, as the DoH and DoQ front ends read one.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::dns_message(data));
