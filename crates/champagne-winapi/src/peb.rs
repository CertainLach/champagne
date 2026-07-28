use std::sync::atomic::{AtomicU32, Ordering};

use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;

pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_PROC_NOT_FOUND: u32 = 127;
pub const ERROR_ENVVAR_NOT_FOUND: u32 = 203;

#[winfn]
pub fn SetLastError(e: u32) {
	get_tib().set_last_error(e);
}

#[winfn]
pub fn GetLastError() -> u32 {
	get_tib().last_error()
}

#[winfn]
fn SetErrorMode(mode: u32) -> u32 {
	static ERROR_MODE: AtomicU32 = AtomicU32::new(0);
	ERROR_MODE.swap(mode, Ordering::Relaxed)
}
