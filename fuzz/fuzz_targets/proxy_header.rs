//! A PROXY protocol header, version 1 and version 2.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| pqcrypta_proxy::fuzzing::proxy_header(data));
