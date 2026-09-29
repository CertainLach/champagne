use std::ffi::c_void;
use std::process;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};

use champagne_macros::winfn;
use tracing::{trace, warn};

const MEM_COMMIT: u32 = 0x1000;
#[allow(dead_code)]
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_DECOMMIT: u32 = 0x4000;

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

fn win_prot_to_unix(protect: u32) -> i32 {
	match protect & 0xFF {
		PAGE_NOACCESS => libc::PROT_NONE,
		PAGE_READONLY => libc::PROT_READ,
		PAGE_READWRITE | PAGE_WRITECOPY => libc::PROT_READ | libc::PROT_WRITE,
		PAGE_EXECUTE => libc::PROT_EXEC,
		PAGE_EXECUTE_READ => libc::PROT_READ | libc::PROT_EXEC,
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => {
			libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
		}
		_ => libc::PROT_READ | libc::PROT_WRITE,
	}
}

fn needs_exec(protect: u32) -> bool {
	matches!(
		protect & 0xFF,
		PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
	)
}

static SHM_CTR: AtomicU64 = AtomicU64::new(0x8000);

fn alloc_via_shm(size: usize, prot: i32) -> *mut c_void {
	use nix::fcntl::OFlag;
	use nix::sys::mman::{shm_open, shm_unlink};
	use nix::sys::stat::Mode;
	use std::os::fd::AsRawFd;

	let name = format!(
		"/champagne-va-{}-{}",
		process::id(),
		SHM_CTR.fetch_add(1, Ordering::Relaxed)
	);
	let fd = match shm_open(
		name.as_str(),
		OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
		Mode::S_IRWXU,
	) {
		Ok(fd) => fd,
		Err(_) => return null_mut(),
	};
	let _ = shm_unlink(name.as_str());
	if unsafe { libc::ftruncate(fd.as_raw_fd(), size as i64) } != 0 {
		return null_mut();
	}
	let ptr = unsafe { libc::mmap(null_mut(), size, prot, libc::MAP_SHARED, fd.as_raw_fd(), 0) };
	if ptr == libc::MAP_FAILED {
		return null_mut();
	}
	ptr.cast()
}

#[winfn]
fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void {
	if size == 0 {
		return null_mut();
	}
	let prot = win_prot_to_unix(protect);
	trace!("unix prot = {prot}");

	if !addr.is_null() && alloc_type & MEM_COMMIT != 0 {
		if unsafe { libc::mprotect(addr, size, prot) } == 0 {
			return addr;
		}
		return null_mut();
	}

	if needs_exec(protect) {
		return alloc_via_shm(size, prot);
	}

	let ptr = unsafe {
		libc::mmap(
			null_mut(),
			size,
			prot,
			libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
			-1,
			0,
		)
	};
	if ptr == libc::MAP_FAILED {
		null_mut()
	} else {
		ptr.cast()
	}
}

#[winfn]
fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32 {
	if addr.is_null() {
		return 0;
	}
	if free_type & MEM_RELEASE != 0 {
		trace!("release");
		let unmap_size = if size == 0 { 0x10000 } else { size };
		if unsafe { libc::munmap(addr, unmap_size) } == 0 {
			return 1;
		}
		return 0;
	}
	if free_type & MEM_DECOMMIT != 0 {
		trace!("decommit");
		unsafe { libc::madvise(addr, size, libc::MADV_DONTNEED) };
		return 1;
	}
	0
}

#[winfn]
fn VirtualProtect(addr: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32 {
	if !old_protect.is_null() {
		unsafe { old_protect.write(PAGE_READWRITE) };
	}
	let prot = win_prot_to_unix(new_protect);
	trace!(%prot);
	if unsafe { libc::mprotect(addr, size, prot) } == 0 {
		1
	} else {
		warn!("mprotect failed");
		0
	}
}

#[repr(C)]
struct MemoryBasicInformation {
	base_address: *const c_void,
	allocation_base: *const c_void,
	allocation_protect: u32,
	partition_id: u16,
	_pad: u16,
	region_size: usize,
	state: u32,
	protect: u32,
	type_: u32,
}
assert_size!(MemoryBasicInformation, 48);

#[winfn]
fn VirtualQuery(addr: *const c_void, buf: *mut MemoryBasicInformation, len: usize) -> usize {
	if buf.is_null() || len < size_of::<MemoryBasicInformation>() {
		return 0;
	}
	unsafe {
		buf.write(MemoryBasicInformation {
			base_address: addr,
			allocation_base: addr,
			allocation_protect: PAGE_READWRITE,
			partition_id: 0,
			_pad: 0,
			region_size: 0x10000,
			state: MEM_COMMIT,
			protect: PAGE_READWRITE,
			type_: MEM_COMMIT,
		});
	}
	size_of::<MemoryBasicInformation>()
}

#[winfn]
fn VirtualLock(_addr: *mut c_void, _size: usize) -> i32 {
	1
}

#[winfn]
fn VirtualUnlock(_addr: *mut c_void, _size: usize) -> i32 {
	1
}

#[winfn]
fn UnmapViewOfFile(addr: *mut c_void) -> i32 {
	if addr.is_null() {
		return 0;
	}
	if unsafe { libc::munmap(addr, 0x10000) } == 0 {
		1
	} else {
		0
	}
}

#[cfg(not(windows))]
pub mod unix {
	struct VirtualFileMapping {
		fd: i32,
		size: u64,
		protect: u32,
	}

	unsafe impl Send for VirtualFileMapping {}
	unsafe impl Sync for VirtualFileMapping {}
	impl VirtualObject for VirtualFileMapping {}

	use std::ffi::c_void;
	use std::mem;
	use std::ptr::null_mut;

	use champagne_kernel::object::unix::VirtualObject;
	use champagne_kernel::peb::unix::PebLikeUnixExt as _;
	use champagne_macros::winfn;
	use tracing::info;

	use champagne_kernel::tib::get_tib;
	use std::os::unix::io::AsRawFd;
	use std::sync::Arc;

	use crate::file::unix::VirtualFile;

	#[winfn]
	fn MapViewOfFile(
		mapping: *mut c_void,
		desired_access: u32,
		offset_high: u32,
		offset_low: u32,
		size: usize,
	) -> *mut c_void {
		use champagne_kernel::tib::get_tib;

		let peb = get_tib().get_peb();
		let Some(map) = peb
			.private()
			.get_object::<VirtualFileMapping>(mapping as usize)
		else {
			return null_mut();
		};

		let offset = ((offset_high as i64) << 32) | offset_low as i64;
		let map_size = if size == 0 {
			if map.fd >= 0 {
				let mut stat: libc::stat = unsafe { mem::zeroed() };
				if unsafe { libc::fstat(map.fd, &mut stat) } != 0 {
					return null_mut();
				}
				(stat.st_size as usize).saturating_sub(offset as usize)
			} else {
				map.size as usize
			}
		} else {
			size
		};

		let prot = if desired_access & 0x2 != 0 {
			libc::PROT_READ | libc::PROT_WRITE
		} else {
			libc::PROT_READ
		};

		let flags = if map.fd >= 0 {
			libc::MAP_PRIVATE
		} else {
			libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
		};

		info!(
			"MapViewOfFile: fd={}, size={map_size:#x}, offset={offset:#x}, prot={prot}",
			map.fd
		);
		let ptr = unsafe { libc::mmap(null_mut(), map_size, prot, flags, map.fd, offset) };
		if ptr == libc::MAP_FAILED {
			null_mut()
		} else {
			ptr.cast()
		}
	}
	#[winfn]
	fn CreateFileMappingW(
		file: *mut c_void,
		_sec: *const c_void,
		protect: u32,
		max_size_high: u32,
		max_size_low: u32,
		_name: *const u16,
	) -> *mut c_void {
		let size = ((max_size_high as u64) << 32) | max_size_low as u64;
		let fd = if file as usize == usize::MAX || file.is_null() {
			-1i32
		} else {
			let peb = get_tib().get_peb();
			if let Some(fo) = peb.private().get_object::<VirtualFile>(file as usize) {
				fo.fd.as_raw_fd()
			} else {
				-1i32
			}
		};

		info!("CreateFileMappingW: fd={fd}, size={size:#x}, protect={protect:#x}");
		let handle = get_tib()
			.get_peb()
			.private()
			.insert_object(Arc::new(VirtualFileMapping { fd, size, protect }));
		handle as *mut c_void
	}
}
