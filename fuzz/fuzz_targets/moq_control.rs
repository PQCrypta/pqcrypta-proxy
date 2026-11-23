//! A MoQ control message body, decoded and re-encoded to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::moq_control(data));
