use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_macros::winfn;

use crate::heap_raw::{heap_alloc, heap_free, heap_realloc, heap_requested, process_heap};
use crate::peb::{ERROR_NO_MORE_ITEMS, SetLastError};

const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;

// Too much noise, can ba analyzed by normal heap profilers
#[winfn(no_instrument)]
fn HeapAlloc(_heap: *mut c_void, flags: u32, size: usize) -> *mut c_void {
	unsafe { heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0) }
}

// Too much noise, can ba analyzed by normal heap profilers
#[winfn(no_instrument)]
fn HeapFree(_heap: *mut c_void, _flags: u32, mem: *mut c_void) -> i32 {
	unsafe { heap_free(mem) };
	1
}

// Too much noise, can ba analyzed by normal heap profilers
#[winfn(no_instrument)]
fn HeapReAlloc(_heap: *mut c_void, flags: u32, mem: *mut c_void, size: usize) -> *mut c_void {
	if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
		return null_mut();
	}
	unsafe { heap_realloc(mem, size, flags & HEAP_ZERO_MEMORY != 0) }
}

#[winfn]
fn HeapSize(_heap: *mut c_void, _flags: u32, mem: *const c_void) -> usize {
	if mem.is_null() {
		return usize::MAX;
	}
	unsafe { heap_requested(mem) }
}

#[winfn]
fn HeapValidate(_heap: *mut c_void, _flags: u32, _mem: *const c_void) -> i32 {
	1
}

#[winfn]
fn HeapWalk(_heap: *mut c_void, _entry: *mut c_void) -> i32 {
	SetLastError(ERROR_NO_MORE_ITEMS);
	0
}

#[winfn]
fn HeapQueryInformation(
	_heap: *mut c_void,
	_class: i32,
	info: *mut c_void,
	len: usize,
	ret_len: *mut usize,
) -> i32 {
	if !info.is_null() && len >= 4 {
		unsafe { info.cast::<u32>().write(0) };
	}
	if !ret_len.is_null() {
		unsafe { ret_len.write(4) };
	}
	1
}

#[winfn]
fn HeapCompact(_heap: *mut c_void, _flags: u32) -> usize {
	SetLastError(0);
	0
}

#[winfn]
fn LocalFree(mem: *mut c_void) -> *mut c_void {
	unsafe { libc::free(mem) };
	null_mut()
}

#[winfn]
fn GetProcessHeap() -> *mut c_void {
	process_heap()
}

#[winfn]
fn HeapCreate(_options: u32, _initial_size: usize, _max_size: usize) -> *mut c_void {
	process_heap()
}

#[winfn]
fn HeapDestroy(_heap: *mut c_void) -> i32 {
	1
}

#[winfn]
fn HeapSetInformation(_heap: *mut c_void, _class: i32, _info: *const c_void, _len: usize) -> i32 {
	1
}
