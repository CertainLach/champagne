use std::ffi::{CStr, CString, c_void};
use std::path::Path;
use std::ptr::null_mut;
use std::{mem, ptr, str};

use champagne_macros::winfn;
use widestring::U16CStr;

use crate::peb::SetLastError;

const INVALID_HANDLE_VALUE: usize = usize::MAX;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
const FILE_BEGIN: u32 = 0;
const FILE_CURRENT: u32 = 1;
const FILE_END: u32 = 2;

#[repr(C)]
struct FileTime {
	low: u32,
	high: u32,
}

#[repr(C)]
struct ByHandleFileInformation {
	file_attributes: u32,
	creation_time: FileTime,
	last_access_time: FileTime,
	last_write_time: FileTime,
	volume_serial_number: u32,
	file_size_high: u32,
	file_size_low: u32,
	number_of_links: u32,
	file_index_high: u32,
	file_index_low: u32,
}
assert_size!(ByHandleFileInformation, 52);

#[repr(C)]
struct FileBasicInfo {
	creation_time: u64,
	last_access_time: u64,
	last_write_time: u64,
	change_time: u64,
	file_attributes: u32,
	_pad: u32,
}
assert_size!(FileBasicInfo, 40);

#[repr(C)]
struct Win32FindDataW {
	file_attributes: u32,
	creation_time: FileTime,
	last_access_time: FileTime,
	last_write_time: FileTime,
	file_size_high: u32,
	file_size_low: u32,
	reserved0: u32,
	reserved1: u32,
	file_name: [u16; 260],
	alternate_file_name: [u16; 14],
}
assert_size!(Win32FindDataW, 592);

fn case_insensitive_resolve(path: &str) -> String {
	let parts: Vec<&str> = path.split('/').collect();
	let mut resolved = String::new();
	for (i, part) in parts.iter().enumerate() {
		if part.is_empty() {
			if i == 0 {
				resolved.push('/');
			}
			continue;
		}
		let candidate = if resolved.is_empty() {
			part.to_string()
		} else if resolved.ends_with('/') {
			format!("{resolved}{part}")
		} else {
			format!("{resolved}/{part}")
		};
		if Path::new(&candidate).exists() {
			resolved = candidate;
		} else {
			let parent = if resolved.is_empty() { "." } else { &resolved };
			let lower = part.to_ascii_lowercase();
			let found = std::fs::read_dir(parent)
				.ok()
				.and_then(|entries| {
					entries
						.filter_map(|e| e.ok())
						.find(|e| e.file_name().to_string_lossy().to_ascii_lowercase() == lower)
				})
				.map(|e| {
					if resolved.is_empty() || (resolved == ".") {
						e.file_name().to_string_lossy().into_owned()
					} else {
						format!("{resolved}/{}", e.file_name().to_string_lossy())
					}
				});
			resolved = found.unwrap_or(candidate);
		}
	}
	resolved
}

fn translate_path(wide: *const u16) -> Option<String> {
	if wide.is_null() {
		return None;
	}
	let s = unsafe { U16CStr::from_ptr_str(wide) }.to_string_lossy();
	let mut path = s.replace('\\', "/");
	if path.starts_with("/./") {
		return Some(".".to_string());
	}
	if path.starts_with("./") {
		path = path[2..].to_string();
	}
	if path.starts_with("//./") {
		path = path[4..].to_string();
	}
	if path.len() >= 2 && path.as_bytes()[1] == b':' {
		path = path[2..].to_string();
	}
	while path.starts_with('/') {
		path = path[1..].to_string();
	}
	if path.is_empty() {
		return Some(".".to_string());
	}
	if path.starts_with("/Windows/System32/") || path.starts_with("/windows/system32/") {
		return None;
	}
	Some(case_insensitive_resolve(&path))
}

fn _translate_path_a(narrow: *const u8) -> Option<String> {
	if narrow.is_null() {
		return None;
	}
	let s = unsafe { CStr::from_ptr(narrow.cast()) }.to_str().ok()?;
	let mut path = s.replace('\\', "/");
	if path.len() >= 2 && path.as_bytes()[1] == b':' {
		path = path[2..].to_string();
	}
	Some(path)
}

#[winfn]
fn GetFileAttributesW(name: *const u16) -> u32 {
	let Some(path) = translate_path(name) else {
		return INVALID_FILE_ATTRIBUTES;
	};
	let c_path = match CString::new(path.as_bytes()) {
		Ok(s) => s,
		Err(_) => return INVALID_FILE_ATTRIBUTES,
	};
	let mut stat: libc::stat = unsafe { mem::zeroed() };
	if unsafe { libc::stat(c_path.as_ptr(), &mut stat) } != 0 {
		SetLastError(2);
		return INVALID_FILE_ATTRIBUTES;
	}
	if stat.st_mode & libc::S_IFDIR != 0 {
		FILE_ATTRIBUTE_DIRECTORY
	} else {
		FILE_ATTRIBUTE_NORMAL
	}
}

#[winfn]
fn GetFileAttributesExW(name: *const u16, _level: u32, info: *mut c_void) -> i32 {
	let attrs = GetFileAttributesW(name);
	if attrs == INVALID_FILE_ATTRIBUTES {
		return 0;
	}
	if !info.is_null() {
		unsafe {
			let base = info.cast::<u8>();
			ptr::write_bytes(base, 0, 36);
			(base as *mut u32).write(attrs);
		}
	}
	1
}

#[winfn]
fn DeleteFileW(name: *const u16) -> i32 {
	let Some(path) = translate_path(name) else {
		return 0;
	};
	let c_path = match CString::new(path.as_bytes()) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	if unsafe { libc::unlink(c_path.as_ptr()) } == 0 {
		1
	} else {
		0
	}
}

#[winfn]
fn GetFullPathNameW(
	name: *const u16,
	buf_len: u32,
	buf: *mut u16,
	_file_part: *mut *mut u16,
) -> u32 {
	if name.is_null() {
		return 0;
	}
	let s = unsafe { U16CStr::from_ptr_str(name) };
	let len = s.len() + 1;
	if buf.is_null() || buf_len == 0 {
		return len as u32;
	}
	let copy = len.min(buf_len as usize);
	unsafe { buf.copy_from_nonoverlapping(name, copy) };
	if copy < len {
		return len as u32;
	}
	(copy - 1) as u32
}

#[winfn]
fn DeviceIoControl(
	_handle: *mut c_void,
	_code: u32,
	_in_buf: *const c_void,
	_in_size: u32,
	_out_buf: *mut c_void,
	_out_size: u32,
	_returned: *mut u32,
	_overlapped: *mut c_void,
) -> i32 {
	SetLastError(50);
	0
}

fn name_matches_pattern(name: &[u8], pattern: &str) -> bool {
	if pattern == "*.*" || pattern == "*" {
		return true;
	}
	let name_str = str::from_utf8(name).unwrap_or("");
	if let Some(ext) = pattern.strip_prefix("*.") {
		return name_str
			.rsplit('.')
			.next()
			.is_some_and(|e| e.eq_ignore_ascii_case(ext));
	}
	name_str.eq_ignore_ascii_case(pattern)
}

#[winfn]
fn GetDiskFreeSpaceExW(
	_root: *const u16,
	caller_free: *mut u64,
	total: *mut u64,
	total_free: *mut u64,
) -> i32 {
	if !caller_free.is_null() {
		unsafe { caller_free.write(1 << 30) };
	}
	if !total.is_null() {
		unsafe { total.write(1 << 34) };
	}
	if !total_free.is_null() {
		unsafe { total_free.write(1 << 30) };
	}
	1
}

#[winfn]
fn SetFileAttributesW(_name: *const u16, _attrs: u32) -> i32 {
	1
}

#[winfn]
fn MoveFileExW(old: *const u16, new: *const u16, _flags: u32) -> i32 {
	let Some(old_path) = translate_path(old) else {
		return 0;
	};
	let Some(new_path) = translate_path(new) else {
		return 0;
	};
	let c_old = match CString::new(old_path.as_bytes()) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	let c_new = match CString::new(new_path.as_bytes()) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	if unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) } == 0 {
		1
	} else {
		0
	}
}

#[winfn]
fn CreateDirectoryW(path: *const u16, _sec: *const c_void) -> i32 {
	let Some(native) = translate_path(path) else {
		return 0;
	};
	let c_path = match CString::new(native.as_bytes()) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	if unsafe { libc::mkdir(c_path.as_ptr(), 0o755) } == 0 {
		1
	} else {
		0
	}
}

#[winfn]
fn RemoveDirectoryW(path: *const u16) -> i32 {
	let Some(native) = translate_path(path) else {
		return 0;
	};
	let c_path = match CString::new(native.as_bytes()) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	if unsafe { libc::rmdir(c_path.as_ptr()) } == 0 {
		1
	} else {
		0
	}
}

#[winfn]
fn GetFileVersionInfoSizeExW(_flags: u32, _filename: *const u16, handle: *mut u32) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(0) };
	}
	0
}

#[winfn]
fn GetFileVersionInfoExW(
	_flags: u32,
	_filename: *const u16,
	_handle: u32,
	_len: u32,
	_data: *mut c_void,
) -> i32 {
	0
}

#[winfn]
fn VerQueryValueW(
	_data: *const c_void,
	_sub_block: *const u16,
	_buf: *mut *mut c_void,
	_len: *mut u32,
) -> i32 {
	0
}

#[winfn]
fn NtOpenSymbolicLinkObject(handle: *mut *mut c_void, _access: u32, _attrs: *const c_void) -> u32 {
	if !handle.is_null() {
		unsafe { handle.write(null_mut()) };
	}
	0xC0000034
}

#[winfn]
fn NtQuerySymbolicLinkObject(_handle: *mut c_void, _link: *mut c_void, _returned: *mut u32) -> u32 {
	0xC0000008
}

#[winfn]
fn NtQueryVolumeInformationFile(
	_handle: *mut c_void,
	_io_status: *mut c_void,
	_info: *mut c_void,
	_len: u32,
	_class: u32,
) -> u32 {
	0xC0000001
}

#[winfn]
fn QueryDosDeviceW(_name: *const u16, buf: *mut u16, size: u32) -> u32 {
	if buf.is_null() || size < 2 {
		return 0;
	}
	unsafe { buf.write(0) };
	0
}

#[winfn]
fn AreFileApisANSI() -> i32 {
	1
}

#[winfn]
fn SetFileTime(
	_handle: *mut c_void,
	_creation: *const c_void,
	_last_access: *const c_void,
	_last_write: *const c_void,
) -> i32 {
	1
}

#[winfn]
fn SetFileInformationByHandle(
	_handle: *mut c_void,
	_class: u32,
	_info: *const c_void,
	_size: u32,
) -> i32 {
	1
}

#[winfn]
fn LockFile(
	_handle: *mut c_void,
	_offset_low: u32,
	_offset_high: u32,
	_len_low: u32,
	_len_high: u32,
) -> i32 {
	1
}

#[winfn]
fn UnlockFile(
	_handle: *mut c_void,
	_offset_low: u32,
	_offset_high: u32,
	_len_low: u32,
	_len_high: u32,
) -> i32 {
	1
}

#[winfn]
fn GetTempFileNameW(_path: *const u16, _prefix: *const u16, _unique: u32, buf: *mut u16) -> u32 {
	if !buf.is_null() {
		let s: Vec<u16> = "/tmp/champagne_tmp.tmp\0".encode_utf16().collect();
		unsafe { buf.copy_from_nonoverlapping(s.as_ptr(), s.len()) };
	}
	1
}

#[winfn]
fn GetFileAttributesA(name: *const u8) -> u32 {
	if name.is_null() {
		return INVALID_FILE_ATTRIBUTES;
	}
	let s = unsafe { CStr::from_ptr(name.cast()) };
	let path = s.to_string_lossy();
	let c_path = match CString::new(path.as_bytes()) {
		Ok(s) => s,
		Err(_) => return INVALID_FILE_ATTRIBUTES,
	};
	let mut stat: libc::stat = unsafe { mem::zeroed() };
	if unsafe { libc::stat(c_path.as_ptr(), &mut stat) } != 0 {
		SetLastError(2);
		return INVALID_FILE_ATTRIBUTES;
	}
	if stat.st_mode & libc::S_IFDIR != 0 {
		FILE_ATTRIBUTE_DIRECTORY
	} else {
		FILE_ATTRIBUTE_NORMAL
	}
}

#[cfg(not(windows))]
pub mod unix {
	use std::ffi::{CStr, CString, c_void};
	use std::iter::once;
	use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
	use std::sync::Arc;
	use std::{mem, ptr};

	use super::*;

	use champagne_kernel::object::unix::VirtualObject;
	use champagne_kernel::peb::unix::PebLikeUnixExt as _;
	use champagne_kernel::tib::get_tib;
	use champagne_macros::winfn;
	use parking_lot::Mutex;
	use tracing::{trace, warn};
	use widestring::U16CStr;

	use crate::peb::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, SetLastError};

	use super::{
		CREATE_ALWAYS, CREATE_NEW, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY,
		FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_CURRENT, FILE_END, GENERIC_READ, GENERIC_WRITE,
		INVALID_HANDLE_VALUE, OPEN_ALWAYS, OPEN_EXISTING, TRUNCATE_EXISTING, name_matches_pattern,
		translate_path,
	};
	struct FindHandleInner {
		dir: *mut libc::DIR,
		pattern: String,
		_base_path: String,
	}
	struct FindHandle(Mutex<FindHandleInner>);

	unsafe impl Send for FindHandleInner {}
	unsafe impl Sync for FindHandleInner {}
	impl VirtualObject for FindHandle {}

	impl Drop for FindHandleInner {
		fn drop(&mut self) {
			if !self.dir.is_null() {
				unsafe { libc::closedir(self.dir) };
			}
		}
	}

	fn fill_find_data(_find: &FindHandleInner, entry: &libc::dirent, data: *mut Win32FindDataW) {
		if data.is_null() {
			return;
		}
		let name_bytes = unsafe { CStr::from_ptr(entry.d_name.as_ptr()).to_bytes() };
		let attrs = if entry.d_type == libc::DT_DIR {
			FILE_ATTRIBUTE_DIRECTORY
		} else {
			FILE_ATTRIBUTE_ARCHIVE
		};
		let mut find_data = Win32FindDataW {
			file_attributes: attrs,
			creation_time: FileTime { low: 0, high: 0 },
			last_access_time: FileTime { low: 0, high: 0 },
			last_write_time: FileTime { low: 0, high: 0 },
			file_size_high: 0,
			file_size_low: 0,
			reserved0: 0,
			reserved1: 0,
			file_name: [0; 260],
			alternate_file_name: [0; 14],
		};
		for (i, &b) in name_bytes.iter().take(259).enumerate() {
			find_data.file_name[i] = b as u16;
		}
		unsafe { data.write(find_data) };
	}

	pub(crate) struct VirtualFile {
		pub(crate) fd: OwnedFd,
	}

	unsafe impl Send for VirtualFile {}
	unsafe impl Sync for VirtualFile {}
	impl VirtualObject for VirtualFile {}

	fn insert_file_handle(fd: OwnedFd) -> *mut c_void {
		let handle = get_tib()
			.get_peb()
			.private()
			.insert_object(Arc::new(VirtualFile { fd }));
		handle as *mut c_void
	}

	pub fn get_file_fd(handle: *mut c_void) -> Option<i32> {
		let file_obj = get_tib()
			.get_peb()
			.private()
			.get_object::<VirtualFile>(handle as usize)?;
		Some(file_obj.fd.as_raw_fd())
	}

	#[winfn]
	fn FlushFileBuffers(handle: *mut c_void) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			return 0;
		};
		unsafe { libc::fsync(fd) };
		1
	}
	#[winfn]
	fn SetEndOfFile(handle: *mut c_void) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			return 0;
		};
		let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
		if pos < 0 {
			return 0;
		}
		if unsafe { libc::ftruncate(fd, pos) } == 0 {
			1
		} else {
			0
		}
	}

	#[winfn]
	fn FindFirstFileW(name: *const u16, data: *mut Win32FindDataW) -> *mut c_void {
		let Some(path) = translate_path(name) else {
			SetLastError(2);
			return INVALID_HANDLE_VALUE as *mut c_void;
		};

		let (dir_path, pattern) = if let Some(pos) = path.rfind('/') {
			(path[..pos].to_string(), path[pos + 1..].to_string())
		} else {
			(".".to_string(), path.clone())
		};

		let c_dir = match CString::new(dir_path.as_bytes()) {
			Ok(s) => s,
			Err(_) => {
				SetLastError(2);
				return INVALID_HANDLE_VALUE as *mut c_void;
			}
		};
		let dir = unsafe { libc::opendir(c_dir.as_ptr()) };
		if dir.is_null() {
			SetLastError(2);
			return INVALID_HANDLE_VALUE as *mut c_void;
		}

		let find = FindHandleInner {
			dir,
			pattern,
			_base_path: dir_path,
		};

		loop {
			let entry = unsafe { libc::readdir(find.dir) };
			if entry.is_null() {
				SetLastError(18);
				return INVALID_HANDLE_VALUE as *mut c_void;
			}
			let entry = unsafe { &*entry };
			let name_bytes = unsafe { CStr::from_ptr(entry.d_name.as_ptr()).to_bytes() };
			if name_bytes == b"." || name_bytes == b".." {
				continue;
			}
			if name_matches_pattern(name_bytes, &find.pattern) {
				fill_find_data(&find, entry, data);
				let handle = get_tib()
					.get_peb()
					.private()
					.insert_object(Arc::new(FindHandle(Mutex::new(find))));
				return handle as *mut c_void;
			}
		}
	}

	#[winfn]
	fn FindNextFileW(handle: *mut c_void, data: *mut Win32FindDataW) -> i32 {
		let Some(find_mutex) = get_tib()
			.get_peb()
			.private()
			.get_object::<FindHandle>(handle as usize)
		else {
			SetLastError(ERROR_INVALID_HANDLE);
			return 0;
		};
		let find = find_mutex.0.lock();

		loop {
			let entry = unsafe { libc::readdir(find.dir) };
			if entry.is_null() {
				SetLastError(18);
				return 0;
			}
			let entry = unsafe { &*entry };
			let name_bytes = unsafe { CStr::from_ptr(entry.d_name.as_ptr()).to_bytes() };
			if name_bytes == b"." || name_bytes == b".." {
				continue;
			}
			if name_matches_pattern(name_bytes, &find.pattern) {
				fill_find_data(&find, entry, data);
				return 1;
			}
		}
	}

	#[winfn]
	fn FindClose(handle: *mut c_void) -> i32 {
		get_tib().get_peb().private().remove_object(handle as usize);
		1
	}
	#[winfn]
	fn CreateFileW(
		name: *const u16,
		access: u32,
		_share: u32,
		_sec: *const c_void,
		disposition: u32,
		_flags: u32,
		_template: *mut c_void,
	) -> *mut c_void {
		let raw = if !name.is_null() {
			unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy()
		} else {
			String::new()
		};
		let Some(path) = translate_path(name) else {
			trace!("{raw} -> None");
			SetLastError(ERROR_INVALID_PARAMETER);
			return INVALID_HANDLE_VALUE as *mut c_void;
		};
		trace!("{raw} -> {path} (access={access:#x}, disp={disposition})");

		let mut flags = 0i32;
		match disposition {
			CREATE_NEW => flags |= libc::O_CREAT | libc::O_EXCL,
			CREATE_ALWAYS => flags |= libc::O_CREAT | libc::O_TRUNC,
			OPEN_EXISTING => {}
			OPEN_ALWAYS => flags |= libc::O_CREAT,
			TRUNCATE_EXISTING => flags |= libc::O_TRUNC,
			_ => {}
		}
		if access & GENERIC_READ != 0 && access & GENERIC_WRITE != 0 {
			flags |= libc::O_RDWR;
		} else if access & GENERIC_WRITE != 0 {
			flags |= libc::O_WRONLY;
		} else {
			flags |= libc::O_RDONLY;
		}

		let c_path = match CString::new(path.as_bytes()) {
			Ok(s) => s,
			Err(_) => {
				SetLastError(ERROR_INVALID_PARAMETER);
				return INVALID_HANDLE_VALUE as *mut c_void;
			}
		};
		let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o644) };
		if fd < 0 {
			SetLastError(2);
			return INVALID_HANDLE_VALUE as *mut c_void;
		}
		let owned = unsafe { OwnedFd::from_raw_fd(fd) };
		insert_file_handle(owned)
	}

	#[winfn]
	fn CreateFileA(
		name: *const u8,
		access: u32,
		share: u32,
		sec: *const c_void,
		disposition: u32,
		flags: u32,
		template: *mut c_void,
	) -> *mut c_void {
		if name.is_null() {
			SetLastError(ERROR_INVALID_PARAMETER);
			return INVALID_HANDLE_VALUE as *mut c_void;
		}
		let narrow = unsafe { CStr::from_ptr(name.cast()) };
		let wide: Vec<u16> = narrow
			.to_string_lossy()
			.encode_utf16()
			.chain(once(0))
			.collect();
		CreateFileW(
			wide.as_ptr(),
			access,
			share,
			sec,
			disposition,
			flags,
			template,
		)
	}

	#[winfn]
	fn ReadFile(
		handle: *mut c_void,
		buf: *mut c_void,
		len: u32,
		bytes_read: *mut u32,
		_overlapped: *mut c_void,
	) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			if !bytes_read.is_null() {
				unsafe { bytes_read.write(0) };
			}
			return 0;
		};
		let n = unsafe { libc::read(fd, buf, len as usize) };
		trace!("ReadFile({handle:?}, len={len}, n={n})");
		if n < 0 {
			if !bytes_read.is_null() {
				unsafe { bytes_read.write(0) };
			}
			return 0;
		}
		if !bytes_read.is_null() {
			unsafe { bytes_read.write(n as u32) };
		}
		SetLastError(0);
		1
	}

	#[winfn]
	fn WriteFile(
		handle: *mut c_void,
		buf: *const c_void,
		len: u32,
		bytes_written: *mut u32,
		_overlapped: *mut c_void,
	) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			if !bytes_written.is_null() {
				unsafe { bytes_written.write(0) };
			}
			return 0;
		};
		let n = unsafe { libc::write(fd, buf, len as usize) };
		if n < 0 {
			if !bytes_written.is_null() {
				unsafe { bytes_written.write(0) };
			}
			return 0;
		}
		if !bytes_written.is_null() {
			unsafe { bytes_written.write(n as u32) };
		}
		1
	}

	#[winfn]
	fn SetFilePointer(handle: *mut c_void, dist_low: i32, dist_high: *mut i32, method: u32) -> u32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			return 0xFFFFFFFF;
		};
		let high = if dist_high.is_null() {
			0i64
		} else {
			(unsafe { dist_high.read() } as i64) << 32
		};
		let offset = high | (dist_low as u32 as i64);
		let whence = match method {
			FILE_BEGIN => libc::SEEK_SET,
			FILE_CURRENT => libc::SEEK_CUR,
			FILE_END => libc::SEEK_END,
			_ => libc::SEEK_SET,
		};
		let result = unsafe { libc::lseek(fd, offset, whence) };
		if result < 0 {
			return 0xFFFFFFFF;
		}
		if !dist_high.is_null() {
			unsafe { dist_high.write((result >> 32) as i32) };
		}
		result as u32
	}

	#[winfn]
	fn SetFilePointerEx(handle: *mut c_void, distance: i64, new_ptr: *mut i64, method: u32) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			return 0;
		};
		let whence = match method {
			FILE_BEGIN => libc::SEEK_SET,
			FILE_CURRENT => libc::SEEK_CUR,
			FILE_END => libc::SEEK_END,
			_ => libc::SEEK_SET,
		};
		let result = unsafe { libc::lseek(fd, distance, whence) };
		if result < 0 {
			return 0;
		}
		if !new_ptr.is_null() {
			unsafe { new_ptr.write(result) };
		}
		SetLastError(0);
		1
	}

	#[winfn]
	fn GetFileSizeEx(handle: *mut c_void, size: *mut i64) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			return 0;
		};
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		if unsafe { libc::fstat(fd, &mut stat) } != 0 {
			return 0;
		}
		if !size.is_null() {
			unsafe { size.write(stat.st_size) };
		}
		SetLastError(0);
		1
	}
	#[winfn]
	fn GetFileSize(handle: *mut c_void, high: *mut u32) -> u32 {
		let Some(fd) = get_file_fd(handle) else {
			SetLastError(ERROR_INVALID_HANDLE);
			return 0xFFFFFFFF;
		};
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		if unsafe { libc::fstat(fd, &mut stat) } != 0 {
			return 0xFFFFFFFF;
		}
		if !high.is_null() {
			unsafe { high.write((stat.st_size >> 32) as u32) };
		}
		stat.st_size as u32
	}
	#[winfn]
	fn GetFileInformationByHandle(handle: *mut c_void, info: *mut ByHandleFileInformation) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			return 0;
		};
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		if unsafe { libc::fstat(fd, &mut stat) } != 0 {
			return 0;
		}
		if info.is_null() {
			return 0;
		}
		let attrs = if stat.st_mode & libc::S_IFDIR != 0 {
			FILE_ATTRIBUTE_DIRECTORY
		} else {
			FILE_ATTRIBUTE_NORMAL
		};
		unsafe {
			info.write(ByHandleFileInformation {
				file_attributes: attrs,
				creation_time: FileTime { low: 0, high: 0 },
				last_access_time: FileTime { low: 0, high: 0 },
				last_write_time: FileTime { low: 0, high: 0 },
				volume_serial_number: 0,
				file_size_high: (stat.st_size >> 32) as u32,
				file_size_low: stat.st_size as u32,
				number_of_links: 1,
				file_index_high: (stat.st_ino >> 32) as u32,
				file_index_low: stat.st_ino as u32,
			});
		}
		1
	}

	#[winfn]
	fn GetFileTime(
		handle: *mut c_void,
		creation: *mut u64,
		access: *mut u64,
		write: *mut u64,
	) -> i32 {
		let Some(fd) = get_file_fd(handle) else {
			return 0;
		};
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		if unsafe { libc::fstat(fd, &mut stat) } != 0 {
			return 0;
		}
		let unix_to_filetime = |secs: i64| -> u64 { ((secs as u64) + 11644473600) * 10_000_000 };
		let ct = unix_to_filetime(stat.st_ctime);
		let at = unix_to_filetime(stat.st_atime);
		let wt = unix_to_filetime(stat.st_mtime);
		if !creation.is_null() {
			unsafe { creation.write(ct) };
		}
		if !access.is_null() {
			unsafe { access.write(at) };
		}
		if !write.is_null() {
			unsafe { write.write(wt) };
		}
		1
	}

	#[winfn]
	fn GetFileInformationByHandleEx(
		handle: *mut c_void,
		class: u32,
		info: *mut c_void,
		len: u32,
	) -> i32 {
		if info.is_null() || len == 0 {
			return 0;
		}
		let Some(fd) = get_file_fd(handle) else {
			return 0;
		};
		let mut stat: libc::stat = unsafe { mem::zeroed() };
		if unsafe { libc::fstat(fd, &mut stat) } != 0 {
			return 0;
		}
		unsafe { ptr::write_bytes(info.cast::<u8>(), 0, len as usize) };
		let unix_to_filetime = |secs: i64| -> u64 { ((secs as u64) + 11644473600) * 10_000_000 };
		match class {
			1 => {
				if len as usize >= size_of::<FileBasicInfo>() {
					unsafe {
						info.cast::<FileBasicInfo>().write(FileBasicInfo {
							creation_time: unix_to_filetime(stat.st_ctime),
							last_access_time: unix_to_filetime(stat.st_atime),
							last_write_time: unix_to_filetime(stat.st_mtime),
							change_time: unix_to_filetime(stat.st_mtime),
							file_attributes: FILE_ATTRIBUTE_NORMAL,
							_pad: 0,
						});
					}
				}
				1
			}
			7 => {
				if len >= 8 {
					unsafe { (info as *mut u64).write(stat.st_size as u64) };
				}
				1
			}
			_ => {
				warn!("unhandled class {class}");
				0
			}
		}
	}
}
