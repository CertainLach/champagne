use std::ffi::c_void;
use std::ptr::{self, null, null_mut};
use std::{slice, str};

use champagne_kernel::peb::{PebLike as _, get_peb};
use champagne_macros::winfn;

use crate::heap_raw::{heap_alloc, heap_free};
use crate::ldr::override_import;

#[winfn]
fn NtSetInformationProcess(
	_handle: *mut c_void,
	_class: u32,
	_info: *const c_void,
	_len: u32,
) -> u32 {
	0
}

#[winfn]
fn RtlAcquirePebLock() {
	let peb = get_peb();
	unsafe { peb.lock_unbalanced() };
}

#[winfn]
fn RtlReleasePebLock() {
	let peb = get_peb();
	unsafe { peb.unlock_unbalanced() };
}

#[winfn]
fn RtlAllocateHeap(_heap: *mut c_void, flags: u32, size: usize) -> *mut c_void {
	unsafe { heap_alloc(size, flags & 0x8 != 0) }
}

#[winfn]
fn RtlFreeHeap(_heap: *mut c_void, _flags: u32, mem: *mut c_void) -> i32 {
	unsafe { heap_free(mem) };
	1
}

#[winfn]
fn RtlSetHeapInformation(
	_heap: *mut c_void,
	_class: u32,
	_info: *const c_void,
	_len: usize,
) -> u32 {
	0
}

#[winfn]
fn RtlCreateHeap(
	_flags: u32,
	_base: *mut c_void,
	_reserve: usize,
	_commit: usize,
	_lock: *mut c_void,
	_params: *const c_void,
) -> *mut c_void {
	crate::heap_raw::process_heap()
}

#[winfn]
fn RtlNtStatusToDosError(status: u32) -> u32 {
	match status {
		0 => 0,
		0xC0000005 => 998,
		0xC0000008 => 6,
		0xC000000D => 87,
		0xC000000E => 2,
		0xC0000017 => 8,
		0xC0000034 => 2,
		0xC0000035 => 183,
		0xC0000225 => 1168,
		_ => status,
	}
}

#[winfn]
fn LsaNtStatusToWinError(status: u32) -> u32 {
	RtlNtStatusToDosError(status)
}

#[winfn]
fn NtQueryInformationProcess(
	_handle: *mut c_void,
	class: u32,
	info: *mut c_void,
	len: u32,
	ret_len: *mut u32,
) -> u32 {
	if !info.is_null() && len > 0 {
		unsafe { ptr::write_bytes(info.cast::<u8>(), 0, len as usize) };
	}
	const PROCESS_PROTECTION_INFORMATION: u32 = 61;
	if class == PROCESS_PROTECTION_INFORMATION && !info.is_null() && len >= 1 {
		unsafe { info.cast::<u8>().write(0x32) };
		if !ret_len.is_null() {
			unsafe { ret_len.write(1) };
		}
		return 0;
	}
	if !ret_len.is_null() {
		unsafe { ret_len.write(0) };
	}
	0
}

#[winfn]
fn LdrGetDllHandle(
	_search_path: *const u16,
	_flags: *mut u32,
	_name: *const c_void,
	handle: *mut *mut c_void,
) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(null_mut()) };
	}
	0xC0000135
}

#[winfn]
fn LdrLoadDll(
	_search_path: *const u16,
	_flags: *mut u32,
	_name: *const c_void,
	handle: *mut *mut c_void,
) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(null_mut()) };
	}
	0xC0000135
}

#[winfn]
fn LdrUnloadDll(_handle: *mut c_void) -> u32 {
	0
}

#[winfn]
fn LdrGetProcedureAddress(
	_module: *mut c_void,
	name: *const c_void,
	_ordinal: u32,
	addr: *mut *mut c_void,
) -> u32 {
	#[repr(C)]
	struct AnsiString {
		length: u16,
		max_length: u16,
		_pad: u32,
		buffer: *const u8,
	}
	if !name.is_null() {
		let ansi = unsafe { &*(name as *const AnsiString) };
		if !ansi.buffer.is_null() && ansi.length > 0 {
			let s = unsafe { slice::from_raw_parts(ansi.buffer, ansi.length as usize) };
			if let Ok(fn_name) = str::from_utf8(s) {
				// TODO: Import override?
				if let Some(ptr) = override_import("kernel32.dll", fn_name) {
					tracing::debug!("LdrGetProcedureAddress: {fn_name} => builtin");
					if !addr.is_null() {
						unsafe { addr.write(ptr as *mut c_void) };
					}
					return 0;
				}
			}
		}
	}
	if !addr.is_null() {
		unsafe { addr.write(null_mut()) };
	}
	0xC0000139
}

#[winfn(alias(EtwRegister))]
fn EventRegister(
	_guid: *const c_void,
	_callback: *const c_void,
	_context: *mut c_void,
	handle: *mut u64,
) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(0) };
	}
	0
}

#[winfn(alias(EtwUnregister))]
fn EventUnregister(_handle: u64) -> u32 {
	0
}

#[winfn]
fn EventActivityIdControl(_control: u32, _id: *mut c_void) -> u32 {
	0
}

#[winfn]
fn RegisterTraceGuidsW(
	_callback: *const c_void,
	_context: *mut c_void,
	_guid: *const c_void,
	_count: u32,
	_trace_guids: *mut c_void,
	_image: *const u16,
	_resource: *const u16,
	handle: *mut u64,
) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(0) };
	}
	0
}

#[winfn]
fn UnregisterTraceGuids(_handle: u64) -> u32 {
	0
}

#[winfn]
fn TraceMessage(_handle: u64, _flags: u32, _guid: *const c_void, _number: u16) -> u32 {
	0
}

#[winfn]
fn NtClose(_handle: *mut c_void) -> u32 {
	0
}

#[winfn]
fn NtQuerySystemInformation(_class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> u32 {
	if !info.is_null() && len > 0 {
		unsafe { ptr::write_bytes(info.cast::<u8>(), 0, len as usize) };
	}
	if !ret_len.is_null() {
		unsafe { ret_len.write(0) };
	}
	0
}

#[repr(C)]
struct UnicodeString {
	length: u16,
	maximum_length: u16,
	_pad: u32,
	buffer: *const u16,
}

#[winfn]
fn RtlInitUnicodeString(dest: *mut UnicodeString, source: *const u16) {
	if dest.is_null() {
		return;
	}
	if source.is_null() {
		unsafe {
			(*dest).length = 0;
			(*dest).maximum_length = 0;
			(*dest).buffer = null();
		}
		return;
	}
	let mut len = 0u16;
	unsafe {
		while *source.add(len as usize) != 0 {
			len += 1;
		}
	}
	let byte_len = len * 2;
	unsafe {
		(*dest).length = byte_len;
		(*dest).maximum_length = byte_len + 2;
		(*dest).buffer = source;
	}
}

#[repr(C)]
struct AnsiString {
	length: u16,
	maximum_length: u16,
	_pad: u32,
	buffer: *const u8,
}

#[winfn]
fn RtlInitAnsiString(dest: *mut AnsiString, source: *const u8) {
	if dest.is_null() {
		return;
	}
	if source.is_null() {
		unsafe {
			dest.write(AnsiString {
				length: 0,
				maximum_length: 0,
				_pad: 0,
				buffer: null(),
			});
		}
		return;
	}
	let len = unsafe { libc::strlen(source.cast()) } as u16;
	unsafe {
		dest.write(AnsiString {
			length: len,
			maximum_length: len + 1,
			_pad: 0,
			buffer: source,
		});
	}
}

#[winfn]
fn NtQueryObject(
	_handle: *mut c_void,
	_class: u32,
	info: *mut c_void,
	len: u32,
	ret_len: *mut u32,
) -> u32 {
	if !info.is_null() && len > 0 {
		unsafe { ptr::write_bytes(info.cast::<u8>(), 0, len as usize) };
	}
	if !ret_len.is_null() {
		unsafe { ret_len.write(0) };
	}
	0xC0000004
}

#[winfn]
fn NtQueryEaFile(
	handle: *mut c_void,
	io_status: *mut c_void,
	_buffer: *mut c_void,
	_len: u32,
	_single_entry: i32,
	_ea_list: *mut c_void,
	_ea_list_len: u32,
	_ea_index: *mut u32,
	_restart: i32,
) -> u32 {
	tracing::debug!("NtQueryEaFile({handle:?}) -> STATUS_BUFFER_TOO_SMALL");
	if !io_status.is_null() {
		unsafe { ptr::write_bytes(io_status.cast::<u8>(), 0, 16) };
	}
	0xC0000023
}

#[winfn]
fn NtQueryInformationFile(
	_handle: *mut c_void,
	io_status: *mut c_void,
	info: *mut c_void,
	len: u32,
	_class: u32,
) -> u32 {
	if !info.is_null() && len > 0 {
		unsafe { ptr::write_bytes(info.cast::<u8>(), 0, len as usize) };
	}
	if !io_status.is_null() {
		unsafe { ptr::write_bytes(io_status.cast::<u8>(), 0, 16) };
	}
	0
}

#[winfn]
fn NtCreateFile(
	handle: *mut *mut c_void,
	_access: u32,
	_attributes: *mut c_void,
	io_status: *mut c_void,
	_alloc_size: *mut u64,
	_file_attributes: u32,
	_share_access: u32,
	_disposition: u32,
	_create_options: u32,
	_ea_buffer: *mut c_void,
	_ea_length: u32,
) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(null_mut()) };
	}
	if !io_status.is_null() {
		unsafe { ptr::write_bytes(io_status.cast::<u8>(), 0, 16) };
	}
	0xC0000034
}

#[cfg(not(windows))]
pub mod unix {
	use std::ffi::c_void;
	use std::ptr;

	use champagne_macros::winfn;

	use crate::file::unix::get_file_fd;

	#[winfn]
	fn NtSetInformationFile(
		handle: *mut c_void,
		io_status: *mut c_void,
		info: *mut c_void,
		len: u32,
		class: u32,
	) -> u32 {
		tracing::debug!("NtSetInformationFile(handle={handle:?}, class={class}, len={len})");
		if class == 14 && len >= 8 && !info.is_null() {
			let offset = unsafe { *(info as *const i64) };
			tracing::debug!("  FilePositionInformation: seek to {offset}");
			if let Some(fd) = get_file_fd(handle) {
				unsafe { libc::lseek(fd, offset, libc::SEEK_SET) };
			}
		}
		if !io_status.is_null() {
			unsafe { ptr::write_bytes(io_status.cast::<u8>(), 0, 16) };
		}
		0
	}
}
