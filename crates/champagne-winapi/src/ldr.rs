use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_void};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use champagne_kernel::peb::{PebLike as _, get_peb};
use champagne_loader::ExportedFnRaw as _;
use champagne_macros::winfn;
use tracing::{debug, trace, warn};
use widestring::U16CStr;

use crate::peb::{
	ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND,
	SetLastError,
};
use crate::{WinFn, to_wide};

const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;

static KERNEL32_MODULE: u8 = 0;
static MAIN_MODULE: u8 = 0;

fn main_module_handle() -> *mut c_void {
	(&raw const MAIN_MODULE).cast_mut().cast()
}

fn kernel32_handle() -> *mut c_void {
	(&raw const KERNEL32_MODULE).cast_mut().cast()
}

fn module_handle_from_address(address: *const c_void) -> Option<*mut c_void> {
	let peb = get_peb();
	let entry = peb.find_entry_by_pc(address as usize)?;
	Some(entry.base().cast_mut().cast())
}

fn module_handle(name: &str) -> Option<*mut c_void> {
	let lowered = name.to_lowercase();
	let stem = lowered.strip_suffix(".dll").unwrap_or(&lowered);
	let peb = get_peb();
	if let Some(entry) = peb.find_entry(&format!("{stem}.dll")) {
		return Some(entry.base().cast_mut().cast());
	}
	if matches!(
		stem,
		"kernel32"
			| "kernelbase"
			| "ntdll" | "advapi32"
			| "ws2_32"
			| "crypt32"
			| "bcrypt"
			| "wintrust"
			| "ole32" | "rpcrt4"
			| "secur32"
			| "user32"
			| "userenv"
			| "version"
			| "shell32"
			| "shlwapi"
			| "iphlpapi"
			| "setupapi"
			| "wtsapi32"
			| "wofutil"
			| "wldp"
	) || stem.starts_with("api-ms-win-")
	{
		return Some(kernel32_handle());
	}
	None
}
pub fn override_import(_module: &str, name: &str) -> Option<usize> {
	static TABLE: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
	TABLE
		.get_or_init(|| {
			inventory::iter::<WinFn>
				.into_iter()
				.map(|f| (f.name, (f.ptr)()))
				.collect()
		})
		.get(name)
		.copied()
}

#[winfn(alias(LoadLibraryW))]
fn LoadLibraryExW(name: *const u16, _file: *const (), _flags: u32) -> *const () {
	if name.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return null();
	}
	let name = unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy();
	trace!(%name);
	let stem = name.rsplit(['\\', '/']).next().unwrap_or(&name);
	match module_handle(stem) {
		Some(handle) => {
			debug!("dyn load of already mapped {stem}");
			handle.cast()
		}
		None => {
			debug!("dyn load of unmapped {stem}, returning synthetic handle");
			kernel32_handle().cast_const().cast()
		}
	}
}

#[winfn]
fn FreeLibrary(_module: *const ()) -> i32 {
	1
}

#[winfn]
fn GetProcAddress(module: *const (), proc: *const c_char) -> *const () {
	if (proc as usize) < 0x10000 {
		warn!("get proc by ordinal #{}: unsupported", proc as usize);
		SetLastError(ERROR_PROC_NOT_FOUND);
		return null();
	}
	let Ok(name) = (unsafe { CStr::from_ptr(proc) }).to_str() else {
		SetLastError(ERROR_PROC_NOT_FOUND);
		return null();
	};
	trace!(%name);
	let peb = get_peb();
	if let Some(entry) = peb.find_entry_by_pc(module as usize)
		&& let Ok(ptr) = entry.exported_fn_raw(name)
	{
		return ptr;
	}
	if let Some(ptr) = override_import("kernel32.dll", name) {
		trace!("found builtin");
		return ptr as *const ();
	}
	warn!("get proc not found: {name}");
	SetLastError(ERROR_PROC_NOT_FOUND);
	null()
}

#[winfn]
fn GetModuleFileNameW(_module: *mut c_void, buf: *mut u16, size: u32) -> u32 {
	static NAME: OnceLock<Vec<u16>> = OnceLock::new();
	let name = NAME.get_or_init(|| to_wide(r"C:\main.exe"));
	if buf.is_null() || size == 0 {
		return 0;
	}
	let copy = name.len().min(size as usize);
	unsafe { buf.copy_from_nonoverlapping(name.as_ptr(), copy) };
	// Truncation only happens when the name with its terminator does not
	// fit; an exact fit is a success, otherwise the usual grow-the-buffer
	// loop never terminates.
	if name.len() > size as usize {
		unsafe { buf.add(copy - 1).write(0) };
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return size;
	}
	copy as u32 - 1
}

#[winfn]
fn GetModuleHandleW(name: *const u16) -> *mut c_void {
	if name.is_null() {
		return main_module_handle();
	}
	let name = unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy();
	match module_handle(&name) {
		Some(handle) => handle,
		None => {
			warn!("module not found: {name}");
			SetLastError(ERROR_MOD_NOT_FOUND);
			null_mut()
		}
	}
}

#[winfn]
fn GetModuleHandleExW(flags: u32, name: *const u16, out: *mut *mut c_void) -> i32 {
	if out.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if name.is_null() {
		unsafe { out.write(main_module_handle()) };
		return 1;
	}
	// With this flag the argument is an address inside the module, not a
	// string, so it must never be read as one.
	let found = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
		module_handle_from_address(name.cast())
	} else {
		let name = unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy();
		module_handle(&name)
	};
	match found {
		Some(handle) => {
			unsafe { out.write(handle) };
			1
		}
		None => {
			warn!("module not found for GetModuleHandleEx, flags {flags:#x}");
			unsafe { out.write(null_mut()) };
			SetLastError(ERROR_MOD_NOT_FOUND);
			0
		}
	}
}
