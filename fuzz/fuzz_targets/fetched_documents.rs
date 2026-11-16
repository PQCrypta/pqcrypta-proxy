//! A crawler's published address ranges, and the fingerprint corpus as stored.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::fetched_documents(data));
