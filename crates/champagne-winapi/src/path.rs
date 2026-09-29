use std::ffi::CStr;

use champagne_macros::winfn;
use widestring::U16CStr;

use crate::to_wide;

fn write_wide(buf: *mut u16, size: u32, s: &str) -> u32 {
	let wide = to_wide(s);
	if buf.is_null() || size == 0 {
		return wide.len() as u32;
	}
	let copy = wide.len().min(size as usize);
	unsafe { buf.copy_from_nonoverlapping(wide.as_ptr(), copy) };
	if copy < wide.len() {
		unsafe { buf.add(copy - 1).write(0) };
		return size;
	}
	(copy - 1) as u32
}

#[winfn(alias(GetSystemWow64DirectoryW))]
fn GetSystemDirectoryW(buf: *mut u16, size: u32) -> u32 {
	write_wide(buf, size, r"C:\Windows\System32")
}

#[winfn]
fn GetSystemWindowsDirectoryW(buf: *mut u16, size: u32) -> u32 {
	write_wide(buf, size, r"C:\Windows")
}

#[winfn(alias(GetTempPath2W))]
fn GetTempPathW(size: u32, buf: *mut u16) -> u32 {
	write_wide(buf, size, r"C:\Temp\")
}

#[winfn]
fn GetLogicalDrives() -> u32 {
	0x4
}

#[winfn]
fn GetCurrentDirectoryW(size: u32, buf: *mut u16) -> u32 {
	write_wide(buf, size, r"C:\")
}

#[winfn]
fn SetCurrentDirectoryW(_path: *const u16) -> i32 {
	1
}

#[winfn]
fn GetDriveTypeW(_root: *const u16) -> u32 {
	3
}

#[winfn]
fn GetLongPathNameW(short: *const u16, long: *mut u16, size: u32) -> u32 {
	if short.is_null() {
		return 0;
	}
	let s = unsafe { U16CStr::from_ptr_str(short) };
	let len = s.len() + 1;
	if long.is_null() || size == 0 {
		return len as u32;
	}
	let copy = len.min(size as usize);
	unsafe { long.copy_from_nonoverlapping(short, copy) };
	if copy < len {
		return len as u32;
	}
	(copy - 1) as u32
}

#[winfn]
fn GetLongPathNameA(short: *const u8, long: *mut u8, size: u32) -> u32 {
	if short.is_null() {
		return 0;
	}
	let s = unsafe { CStr::from_ptr(short.cast()) };
	let len = s.to_bytes_with_nul().len();
	if long.is_null() || size == 0 {
		return len as u32;
	}
	let copy = len.min(size as usize);
	unsafe { long.copy_from_nonoverlapping(short, copy) };
	if copy < len {
		return len as u32;
	}
	(copy - 1) as u32
}

#[winfn]
fn GetComputerNameExW(_name_type: u32, buf: *mut u16, size: *mut u32) -> i32 {
	let name = "CHAMPAGNE";
	let wide = to_wide(name);
	if !size.is_null() {
		let avail = unsafe { size.read() } as usize;
		if buf.is_null() || avail < wide.len() {
			unsafe { size.write(wide.len() as u32) };
			return 0;
		}
		unsafe {
			buf.copy_from_nonoverlapping(wide.as_ptr(), wide.len());
			size.write((wide.len() - 1) as u32);
		}
	}
	1
}
