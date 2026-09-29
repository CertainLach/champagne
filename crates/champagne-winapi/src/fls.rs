use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_kernel::peb::PebLike as _;
use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;

#[winfn]
fn FlsAlloc(_callback: *const c_void) -> u32 {
	let peb = get_tib().get_peb();
	let mut peb = peb.lock();
	peb.tls_alloc().unwrap_or(u32::MAX)
}

#[winfn]
fn FlsFree(index: u32) -> i32 {
	let peb = get_tib().get_peb();
	peb.lock().tls_free(index);
	1
}

#[winfn]
fn FlsGetValue(index: u32) -> *mut c_void {
	get_tib().tls_get(index).unwrap_or(null_mut())
}

#[winfn]
fn FlsSetValue(index: u32, data: *mut c_void) -> i32 {
	get_tib().tls_set(index, data);
	1
}
