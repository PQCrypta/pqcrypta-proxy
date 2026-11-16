//! A session ticket as a client presents it, and one sealed and opened again.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::session_ticket(data));
