use std::ffi::c_void;
use std::ptr::null_mut;

const HEAP_HEADER: usize = 16;

static PROCESS_HEAP: u8 = 0;
pub fn process_heap() -> *mut c_void {
	(&raw const PROCESS_HEAP).cast_mut().cast()
}

pub unsafe fn heap_alloc(size: usize, zero: bool) -> *mut c_void {
	let Some(total) = size.checked_add(HEAP_HEADER) else {
		return null_mut();
	};
	let raw = unsafe {
		if zero {
			libc::calloc(1, total)
		} else {
			libc::malloc(total)
		}
	};
	if raw.is_null() {
		return null_mut();
	}
	unsafe {
		raw.cast::<usize>().write(size);
		raw.cast::<u8>().add(HEAP_HEADER).cast()
	}
}

unsafe fn heap_base(mem: *mut c_void) -> *mut c_void {
	unsafe { mem.cast::<u8>().sub(HEAP_HEADER).cast() }
}

pub unsafe fn heap_requested(mem: *const c_void) -> usize {
	unsafe { heap_base(mem.cast_mut()).cast::<usize>().read() }
}

pub unsafe fn heap_free(mem: *mut c_void) {
	if !mem.is_null() {
		unsafe { libc::free(heap_base(mem)) };
	}
}

pub unsafe fn heap_realloc(mem: *mut c_void, size: usize, zero: bool) -> *mut c_void {
	if mem.is_null() {
		return unsafe { heap_alloc(size, zero) };
	}
	let old = unsafe { heap_requested(mem) };
	let Some(total) = size.checked_add(HEAP_HEADER) else {
		return null_mut();
	};
	let raw = unsafe { libc::realloc(heap_base(mem), total) };
	if raw.is_null() {
		return null_mut();
	}
	unsafe {
		raw.cast::<usize>().write(size);
		let new: *mut c_void = raw.cast::<u8>().add(HEAP_HEADER).cast();
		if zero && size > old {
			libc::memset(new.cast::<u8>().add(old).cast(), 0, size - old);
		}
		new
	}
}
