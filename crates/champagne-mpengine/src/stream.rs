use std::ffi::{CStr, c_void};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::{ptr, slice, str};

use crate::defender::*;

pub struct ScanContext {
	pub file: File,
	pub name_wide: Vec<u16>,
}

unsafe extern "win64" fn read_stream(
	this: *mut c_void,
	offset: u64,
	buffer: *mut c_void,
	size: u32,
	size_read: *mut u32,
) -> u32 {
	let ctx = unsafe { &mut *this.cast::<ScanContext>() };
	if ctx.file.seek(SeekFrom::Start(offset)).is_err() {
		if !size_read.is_null() {
			unsafe { size_read.write(0) };
		}
		return 0;
	}
	let buf = unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), size as usize) };
	match ctx.file.read(buf) {
		Ok(n) => {
			if !size_read.is_null() {
				unsafe { size_read.write(n as u32) };
			}
			1
		}
		Err(_) => {
			if !size_read.is_null() {
				unsafe { size_read.write(0) };
			}
			0
		}
	}
}

unsafe extern "win64" fn write_stream(
	_this: *mut c_void,
	_offset: u64,
	_buffer: *const c_void,
	_size: u32,
	_written: *mut u32,
) -> u32 {
	0
}

unsafe extern "win64" fn get_stream_size(this: *mut c_void, file_size: *mut u64) -> u32 {
	let ctx = unsafe { &mut *this.cast::<ScanContext>() };
	match ctx.file.seek(SeekFrom::End(0)) {
		Ok(size) => {
			if !file_size.is_null() {
				unsafe { file_size.write(size) };
			}
			1
		}
		Err(_) => 0,
	}
}

unsafe extern "win64" fn set_stream_size(_this: *mut c_void, _size: *mut u64) -> u32 {
	0
}

unsafe extern "win64" fn get_stream_name(this: *mut c_void) -> *const u16 {
	let ctx = unsafe { &*this.cast::<ScanContext>() };
	ctx.name_wide.as_ptr()
}

unsafe extern "win64" fn set_stream_attributes(
	_this: *mut c_void,
	_attr: u32,
	_data: *const c_void,
	_size: u32,
) -> u32 {
	0
}

unsafe extern "win64" fn get_stream_attributes(
	_this: *mut c_void,
	_attr: u32,
	_data: *mut c_void,
	_size: u32,
	_written: *mut u32,
) -> u32 {
	0
}

pub unsafe extern "win64" fn engine_scan_callback(scan: *mut ScanStruct) -> u32 {
	let flags = unsafe { ptr::addr_of!((*scan).flags).read_unaligned() };
	let virus_name = unsafe { &(*scan).virus_name };
	let name_end = virus_name
		.iter()
		.position(|&b| b == 0)
		.unwrap_or(virus_name.len());
	let name = str::from_utf8(&virus_name[..name_end]).unwrap_or("<invalid>");

	if flags & SCAN_MEMBERNAME != 0 {
		eprintln!("Scanning archive member {name}");
	}
	if flags & SCAN_FILENAME != 0 {
		let fname = unsafe {
			let ptr = ptr::addr_of!((*scan).file_name).read_unaligned();
			if !ptr.is_null() {
				CStr::from_ptr(ptr.cast()).to_str().unwrap_or("<invalid>")
			} else {
				"<null>"
			}
		};
		eprintln!("Scanning {fname}");
	}
	if flags & SCAN_PACKERSTART != 0 {
		eprintln!("Packer {name} identified.");
	}
	if flags & SCAN_ENCRYPTED != 0 {
		eprintln!("File is encrypted.");
	}
	if flags & SCAN_CORRUPT != 0 {
		eprintln!("File may be corrupt.");
	}
	if flags & SCAN_FILETYPE != 0 {
		let fname = unsafe {
			let ptr = ptr::addr_of!((*scan).file_name).read_unaligned();
			if !ptr.is_null() {
				CStr::from_ptr(ptr.cast()).to_str().unwrap_or("<invalid>")
			} else {
				"<null>"
			}
		};
		eprintln!("File {fname} is identified as {name}");
	}
	if flags & 0x08000022 != 0 || flags & 0x40010000 == 0x40010000 {
		eprintln!("{name}");
	}
	0
}

pub fn make_descriptor(ctx: *mut ScanContext) -> StreamBufferDescriptor {
	StreamBufferDescriptor {
		user_ptr: ctx.cast(),
		read: read_stream,
		write: write_stream,
		get_size: get_stream_size,
		set_size: set_stream_size,
		get_name: get_stream_name,
		set_attributes: set_stream_attributes,
		get_attributes: get_stream_attributes,
	}
}
