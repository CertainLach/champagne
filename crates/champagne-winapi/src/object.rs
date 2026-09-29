use std::ffi::c_void;

use champagne_macros::winfn;
use tracing::trace;

pub const INVALID_HANDLE_VALUE: usize = usize::MAX;

const MAXIMUM_WAIT_OBJECTS: usize = 64;
const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
const FILE_TYPE_CHAR: u32 = 2;
const FILE_TYPE_DISK: u32 = 1;

fn std_handle_fd(handle: *mut c_void) -> Option<i32> {
	match handle as usize {
		1 => Some(0),
		2 => Some(1),
		3 => Some(2),
		_ => None,
	}
}

#[allow(clippy::manual_dangling_ptr)]
#[winfn]
fn GetStdHandle(which: u32) -> *mut c_void {
	match which {
		STD_INPUT_HANDLE => 1usize as *mut c_void,
		STD_OUTPUT_HANDLE => 2usize as *mut c_void,
		STD_ERROR_HANDLE => 3usize as *mut c_void,
		_ => INVALID_HANDLE_VALUE as *mut c_void,
	}
}

#[winfn]
fn SetStdHandle(_which: u32, _handle: *mut c_void) -> i32 {
	1
}

#[winfn]
fn GetFileType(handle: *mut c_void) -> u32 {
	let result = match std_handle_fd(handle) {
		Some(_) => FILE_TYPE_CHAR,
		None => FILE_TYPE_DISK,
	};
	trace!("GetFileType({:?}) = {}", handle, result);
	result
}

#[cfg(not(windows))]
pub mod unix {
	use std::ffi::c_void;
	use std::slice;

	use champagne_kernel::object::WAIT_FAILED;
	use champagne_kernel::object::unix::{wait_object_handle, wait_object_handles};
	use champagne_kernel::peb::unix::PebLikeUnixExt as _;
	use champagne_kernel::thread::CURRENT_THREAD_PSEUDO;
	use champagne_kernel::tib::get_tib;
	use champagne_macros::winfn;
	use tracing::warn;

	use crate::peb::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, SetLastError};

	use super::MAXIMUM_WAIT_OBJECTS;

	#[winfn]
	fn WaitForSingleObject(handle: *mut c_void, timeout: u32) -> u32 {
		wait_object_handle(handle, timeout).unwrap_or_else(|| {
			warn!("WaitForSingleObject on unknown handle {handle:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			WAIT_FAILED
		})
	}

	#[winfn]
	fn WaitForMultipleObjects(
		count: u32,
		handles: *const *mut c_void,
		wait_all: i32,
		timeout: u32,
	) -> u32 {
		if handles.is_null() || count == 0 || count as usize > MAXIMUM_WAIT_OBJECTS {
			SetLastError(ERROR_INVALID_PARAMETER);
			return WAIT_FAILED;
		}
		let handles = unsafe { slice::from_raw_parts(handles, count as usize) };
		wait_object_handles(handles, wait_all, timeout).unwrap_or_else(|| {
			warn!("WaitForMultipleObjects on unknown handles {handles:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			WAIT_FAILED
		})
	}

	#[winfn]
	fn CloseHandle(handle: *mut c_void) -> i32 {
		if get_tib().get_peb().private().remove_object(handle as usize) {
			return 1;
		}
		match handle as usize {
			// std handles, the current process and current thread pseudo handles
			1..=3 | usize::MAX | CURRENT_THREAD_PSEUDO => 1,
			_ => {
				warn!("close unknown handle {handle:?}");
				SetLastError(ERROR_INVALID_HANDLE);
				0
			}
		}
	}

	#[winfn]
	fn DuplicateHandle(
		_source_process: *mut c_void,
		source: *mut c_void,
		_target_process: *mut c_void,
		target: *mut *mut c_void,
		_access: u32,
		_inherit: i32,
		_options: u32,
	) -> i32 {
		if target.is_null() {
			return 0;
		}
		let Some(handle) = get_tib()
			.get_peb()
			.private()
			.duplicate_object(source as usize)
		else {
			warn!("duplicate of unknown handle {source:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			return 0;
		};
		unsafe { target.write(handle as *mut c_void) };
		1
	}
}
