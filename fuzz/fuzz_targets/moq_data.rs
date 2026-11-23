//! MoQ datagrams, subgroup streams and FETCH streams.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::moq_data(data));
