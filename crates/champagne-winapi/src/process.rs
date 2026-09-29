use std::ffi::c_void;
use std::process::exit;

use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;
use tracing::{info, warn};

use crate::object::INVALID_HANDLE_VALUE;
use crate::peb::{ERROR_INVALID_HANDLE, SetLastError};

#[winfn]
fn GetCurrentProcessId() -> u32 {
	get_tib().process_id()
}

#[winfn]
fn ExitProcess(code: u32) {
	info!("image requested exit: {code}");
	exit(code as i32)
}

#[winfn]
fn TerminateProcess(process: *mut c_void, code: u32) -> i32 {
	if process as usize != INVALID_HANDLE_VALUE {
		warn!("TerminateProcess on a handle that is not the current process");
		SetLastError(ERROR_INVALID_HANDLE);
		return 0;
	}
	info!("image requested termination: {code}");
	exit(code as i32)
}

#[winfn]
fn GetCurrentProcess() -> *mut c_void {
	INVALID_HANDLE_VALUE as *mut c_void
}
