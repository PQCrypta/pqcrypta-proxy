//! OpenSSL's memory, from the proxy's own allocator.
//!
//! The proxy's allocations go through mimalloc, its global allocator.
//! OpenSSL's did not: every TLS-over-TCP connection's SSL object, record
//! buffers and handshake state, and the OCSP and certificate work, came from
//! glibc malloc, whose per-thread arenas each keep what was freed into them
//! until the arena itself goes. One allocator for the whole process is one
//! that returns memory to the system the same way everywhere (mimalloc
//! purges freed pages after a short delay, and at once under memory pressure,
//! [`crate::memory_pressure`]), and one whose figures describe all of it.
//!
//! OpenSSL accepts other allocation functions only before it has allocated
//! anything, so [`route_to_mimalloc`] is the first thing `main` does.

#![allow(unsafe_code)] // OpenSSL's and mimalloc's C entry points

use std::ffi::{c_char, c_int, c_void};

type MallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

unsafe extern "C" {
    // OpenSSL 3.0 and later (crypto/mem.c); openssl-sys binds neither.
    fn CRYPTO_set_mem_functions(m: MallocFn, r: ReallocFn, f: FreeFn) -> c_int;
    fn CRYPTO_get_mem_functions(
        m: *mut Option<MallocFn>,
        r: *mut Option<ReallocFn>,
        f: *mut Option<FreeFn>,
    );
}

unsafe extern "C" fn allocate(size: usize, _file: *const c_char, _line: c_int) -> *mut c_void {
    // SAFETY: mi_malloc has malloc's contract, including for size 0 (a
    // unique pointer that may be freed), and the same alignment.
    unsafe { libmimalloc_sys::mi_malloc(size) }
}

unsafe extern "C" fn reallocate(
    pointer: *mut c_void,
    size: usize,
    _file: *const c_char,
    _line: c_int,
) -> *mut c_void {
    // SAFETY: `pointer` is null or came from `allocate`/`reallocate`, since
    // these functions are installed before OpenSSL allocates anything.
    unsafe { libmimalloc_sys::mi_realloc(pointer, size) }
}

unsafe extern "C" fn release(pointer: *mut c_void, _file: *const c_char, _line: c_int) {
    // SAFETY: as for `reallocate`; mi_free accepts null.
    unsafe { libmimalloc_sys::mi_free(pointer) }
}

/// Have OpenSSL allocate through mimalloc. False when OpenSSL has allocated
/// already and keeps its own functions: called first in `main`, it does not.
pub fn route_to_mimalloc() -> bool {
    // SAFETY: the three functions have the signatures OpenSSL declares
    // (CRYPTO_malloc_fn, CRYPTO_realloc_fn, CRYPTO_free_fn); OpenSSL refuses
    // them once any allocation of its own exists, so no memory from one
    // allocator is ever given to the other.
    unsafe { CRYPTO_set_mem_functions(allocate, reallocate, release) == 1 }
}

/// Whether OpenSSL allocates through mimalloc now.
pub fn routed() -> bool {
    let mut m: Option<MallocFn> = None;
    let mut r: Option<ReallocFn> = None;
    let mut f: Option<FreeFn> = None;
    // SAFETY: CRYPTO_get_mem_functions writes one function pointer (or null)
    // through each of the three, which are valid for those writes.
    unsafe { CRYPTO_get_mem_functions(&raw mut m, &raw mut r, &raw mut f) };
    m.is_some_and(|m| std::ptr::fn_addr_eq(m, allocate as MallocFn))
        && r.is_some_and(|r| std::ptr::fn_addr_eq(r, reallocate as ReallocFn))
        && f.is_some_and(|f| std::ptr::fn_addr_eq(f, release as FreeFn))
}
