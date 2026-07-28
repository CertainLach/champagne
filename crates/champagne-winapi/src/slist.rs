use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_kernel::peb::PebLike as _;
use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;

#[winfn]
fn InitializeSListHead(head: *mut *mut c_void) {
	if !head.is_null() {
		unsafe { head.write_bytes(0, 2) };
	}
}

#[winfn]
fn QueryDepthSList(head: *mut *mut c_void) -> u16 {
	let mut n = 0u16;
	let mut cur = unsafe { head.read() };
	while !cur.is_null() {
		n = n.saturating_add(1);
		cur = unsafe { cur.cast::<*mut c_void>().read() };
	}
	n
}

// The SList API is contractually lock-free and atomic. A real
// implementation needs a double width compare exchange over the whole
// SLIST_HEADER to defeat ABA; a single lock is not lock-free but it is at
// least atomic, which is what callers actually depend on.
#[winfn]
fn InterlockedPopEntrySList(head: *mut *mut c_void) -> *mut c_void {
	let _guard = get_tib().get_peb().private().slist_lock();
	unsafe {
		let first = head.read();
		if first.is_null() {
			return null_mut();
		}
		head.write(first.cast::<*mut c_void>().read());
		first
	}
}

#[winfn]
fn InterlockedPushEntrySList(head: *mut *mut c_void, entry: *mut *mut c_void) -> *mut c_void {
	let _guard = get_tib().get_peb().private().slist_lock();
	unsafe {
		let prev = head.read();
		entry.write(prev);
		head.write(entry.cast());
		prev
	}
}

#[winfn]
fn InterlockedFlushSList(head: *mut *mut c_void) -> *mut c_void {
	let _guard = get_tib().get_peb().private().slist_lock();
	unsafe {
		let prev = head.read();
		head.write(null_mut());
		prev
	}
}
