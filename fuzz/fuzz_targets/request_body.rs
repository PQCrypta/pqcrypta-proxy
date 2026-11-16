//! A request body and its Content-Encoding: never decoded past the limit.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::request_body(data));
