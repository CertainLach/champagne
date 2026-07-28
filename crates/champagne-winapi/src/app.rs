use std::env;
use std::ffi::{CStr, c_void};
use std::iter::once;
use std::mem::offset_of;
use std::os::raw::c_char;
use std::sync::OnceLock;

use champagne_macros::winfn;
use tracing::debug;
use widestring::U16CStr;

use crate::peb::{ERROR_ENVVAR_NOT_FOUND, SetLastError};

#[repr(C)]
struct StartupInfoW {
	cb: u32,
	lp_reserved: *mut u16,
	lp_desktop: *mut u16,
	lp_title: *mut u16,
	dw_x: u32,
	dw_y: u32,
	dw_x_size: u32,
	dw_y_size: u32,
	dw_x_count_chars: u32,
	dw_y_count_chars: u32,
	dw_fill_attribute: u32,
	dw_flags: u32,
	w_show_window: u16,
	cb_reserved2: u16,
	lp_reserved2: *mut u8,
	h_std_input: *mut c_void,
	h_std_output: *mut c_void,
	h_std_error: *mut c_void,
}
const _: () = assert!(size_of::<StartupInfoW>() == 104);
const _: () = assert!(offset_of!(StartupInfoW, h_std_input) == 80);

fn emit_env<T: Copy + Default>(value: &[T], buf: *mut T, size: u32) -> u32 {
	if buf.is_null() || value.len() + 1 > size as usize {
		return value.len() as u32 + 1;
	}
	unsafe {
		buf.copy_from_nonoverlapping(value.as_ptr(), value.len());
		buf.add(value.len()).write(T::default());
	}
	value.len() as u32
}

fn wide(cell: &'static OnceLock<Vec<u16>>, s: &str) -> *mut u16 {
	cell.get_or_init(|| s.encode_utf16().chain(once(0)).collect())
		.as_ptr()
		.cast_mut()
}

#[winfn]
fn GetCommandLineW() -> *mut u16 {
	static CMD: OnceLock<Vec<u16>> = OnceLock::new();
	wide(&CMD, "dllloader")
}

#[winfn]
fn GetCommandLineA() -> *const c_char {
	// Must be writable: plenty of argv parsers tokenize it in place.
	static CMD: OnceLock<Box<[u8]>> = OnceLock::new();
	CMD.get_or_init(|| Box::from(*b"dllloader\0"))
		.as_ptr()
		.cast()
}

/// Must agree with GetEnvironmentVariable, which reads the real
/// environment; on Windows both are views of the same block.
#[winfn]
fn GetEnvironmentStringsW() -> *mut u16 {
	static ENV: OnceLock<Vec<u16>> = OnceLock::new();
	ENV.get_or_init(|| {
		let mut block = Vec::new();
		for (key, value) in env::vars() {
			block.extend(format!("{key}={value}").encode_utf16());
			block.push(0);
		}
		block.push(0);
		block
	})
	.as_ptr()
	.cast_mut()
}

#[winfn]
fn FreeEnvironmentStringsW(_env: *mut u16) -> i32 {
	1
}

#[winfn]
fn GetEnvironmentVariableA(name: *const c_char, buf: *mut c_char, size: u32) -> u32 {
	if name.is_null() {
		SetLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
	let Ok(value) = env::var(&*name) else {
		debug!("env {name} is unset");
		SetLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	};
	emit_env(value.as_bytes(), buf.cast(), size)
}

#[winfn]
fn GetEnvironmentVariableW(name: *const u16, buf: *mut u16, size: u32) -> u32 {
	if name.is_null() {
		SetLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	}
	let name = unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy();
	let Ok(value) = env::var(&name) else {
		debug!("env {name} is unset");
		SetLastError(ERROR_ENVVAR_NOT_FOUND);
		return 0;
	};
	let value: Vec<u16> = value.encode_utf16().collect();
	emit_env(&value, buf, size)
}

#[winfn]
fn GetStartupInfoW(info: *mut StartupInfoW) {
	if info.is_null() {
		return;
	}
	unsafe {
		info.write_bytes(0, 1);
		(*info).cb = size_of::<StartupInfoW>() as u32;
	}
}
