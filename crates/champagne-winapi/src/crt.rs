use std::ffi::{CStr, c_char, c_void};
use std::ptr::null_mut;

use champagne_macros::winfn;
use tracing::info;

use crate::heap_raw::{heap_alloc, heap_free, heap_realloc, heap_requested};

#[winfn]
fn malloc(size: usize) -> *mut c_void {
	unsafe { heap_alloc(size, false) }
}

#[winfn]
fn calloc(nobj: usize, size: usize) -> *mut c_void {
	match nobj.checked_mul(size) {
		Some(total) => unsafe { heap_alloc(total, true) },
		None => null_mut(),
	}
}

#[winfn]
fn realloc(mem: *mut c_void, size: usize) -> *mut c_void {
	unsafe { heap_realloc(mem, size, false) }
}

#[winfn(alias(_msize))]
fn msize(mem: *const c_void) -> usize {
	unsafe { heap_requested(mem) }
}

#[winfn]
fn free(mem: *mut c_void) {
	unsafe { heap_free(mem) }
}

#[winfn]
fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
	unsafe { libc::memset(dst, c, n) }
}

#[winfn]
fn memcpy(dst: *mut c_void, c: *const c_void, n: usize) -> *mut c_void {
	unsafe { libc::memcpy(dst, c, n) }
}

#[winfn]
fn setlocale(cat: i32, loc: *const c_char) -> *const c_char {
	let locale = if loc.is_null() {
		None
	} else {
		Some(unsafe { CStr::from_ptr(loc) })
	};
	info!("setlocale! {locale:?}");
	unsafe { libc::setlocale(cat, loc) }
}
