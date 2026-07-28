use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_kernel::object::{Object, get_thread, resolve_thread_pseudo};
use champagne_kernel::peb::PebLike as _;
use champagne_kernel::thread::{exit_current_thread, spawn_thread};
use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;
use tracing::warn;

use crate::object::INVALID_HANDLE_VALUE;
use crate::peb::{
	ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MOD_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY,
	ERROR_NOT_SUPPORTED, SetLastError,
};

#[winfn]
fn DisableThreadLibraryCalls(module: *mut c_void) -> i32 {
	let peb = get_tib().get_peb();
	if peb.disable_thread_calls(module.cast()) {
		return 1;
	}
	warn!("DisableThreadLibraryCalls for unknown module {module:?}");
	get_tib().set_last_error(ERROR_MOD_NOT_FOUND);
	0
}

#[winfn]
fn CreateThread(
	_attributes: *mut c_void,
	stack_size: usize,
	start: *mut c_void,
	parameter: *mut c_void,
	flags: u32,
	thread_id: *mut u32,
) -> *mut c_void {
	if start.is_null() {
		get_tib().set_last_error(ERROR_INVALID_PARAMETER);
		return null_mut();
	}
	match unsafe { spawn_thread(start, parameter, stack_size, flags) } {
		Ok(thread) => {
			if !thread_id.is_null() {
				unsafe { thread_id.write(thread.id) }
			}
			thread.handle
		}
		Err(e) => {
			warn!("CreateThread failed: {e}");
			if !thread_id.is_null() {
				unsafe { thread_id.write(0) };
			}
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			null_mut()
		}
	}
}

#[winfn]
fn ExitThread(code: u32) {
	exit_current_thread(code)
}

const STILL_ACTIVE: u32 = 259;
#[winfn]
fn GetExitCodeThread(handle: *mut c_void, code: *mut u32) -> i32 {
	let handle = resolve_thread_pseudo(handle);
	if code.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let Some(object) = get_thread(handle) else {
		warn!("GetExitCodeThread on unknown handle {handle:?}");
		get_tib().set_last_error(ERROR_INVALID_HANDLE);
		return 0;
	};
	let Object::Thread(t) = &*object else {
		unreachable!("checked above")
	};
	unsafe { code.write(t.state.lock().exit_code.unwrap_or(STILL_ACTIVE)) };
	1
}

#[winfn]
fn ResumeThread(handle: *mut c_void) -> u32 {
	let handle = resolve_thread_pseudo(handle);
	match get_thread(handle) {
		Some(object) => {
			let Object::Thread(t) = &*object else {
				unreachable!("checked above")
			};
			t.resume()
		}
		None => {
			warn!("ResumeThread on unknown handle {handle:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			u32::MAX
		}
	}
}

#[winfn]
fn SuspendThread(handle: *mut c_void) -> u32 {
	let handle = resolve_thread_pseudo(handle);
	match get_thread(handle) {
		Some(object) => {
			let Object::Thread(t) = &*object else {
				unreachable!("checked above")
			};
			warn!("SuspendThread only takes effect before the thread starts");
			t.suspend()
		}
		None => {
			warn!("SuspendThread on unknown handle {handle:?}");
			get_tib().set_last_error(ERROR_INVALID_HANDLE);
			u32::MAX
		}
	}
}

#[winfn]
fn GetThreadId(handle: *mut c_void) -> u32 {
	let handle = resolve_thread_pseudo(handle);
	match get_thread(handle) {
		Some(object) => {
			let Object::Thread(t) = &*object else {
				unreachable!("checked above")
			};
			t.id
		}
		None => {
			SetLastError(ERROR_INVALID_HANDLE);
			0
		}
	}
}

#[winfn]
fn SetThreadPriority(_handle: *mut c_void, _priority: i32) -> i32 {
	1
}

const THREAD_PRIORITY_NORMAL: i32 = 0;
const THREAD_PRIORITY_ERROR_RETURN: i32 = 0x7FFF_FFFF;
#[winfn]
fn GetThreadPriority(handle: *mut c_void) -> i32 {
	let handle = resolve_thread_pseudo(handle);
	if get_thread(handle).is_none() {
		SetLastError(ERROR_INVALID_HANDLE);
		return THREAD_PRIORITY_ERROR_RETURN;
	}
	THREAD_PRIORITY_NORMAL
}

#[winfn]
fn SetThreadStackGuarantee(size: *mut u32) -> i32 {
	if !size.is_null() {
		unsafe { size.write(0) };
	}
	1
}

#[winfn]
fn TerminateThread(_handle: *mut c_void, _code: u32) -> i32 {
	warn!("TerminateThread is not supported, it cannot unwind safely");
	SetLastError(ERROR_NOT_SUPPORTED);
	0
}

#[winfn]
fn GetCurrentThread() -> *mut c_void {
	(INVALID_HANDLE_VALUE - 1) as *mut c_void
}

#[winfn]
fn GetCurrentThreadId() -> u32 {
	get_tib().thread_id()
}
