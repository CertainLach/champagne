use std::ffi::c_void;
use std::hint::spin_loop;
use std::ptr::{self, copy_nonoverlapping, dangling_mut, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use champagne_macros::winfn;
use widestring::U16CStr;

use crate::peb::SetLastError;

#[winfn(alias(DecodePointer))]
fn EncodePointer(i: usize) -> usize {
	!i
}

#[winfn]
fn WerRegisterMemoryBlock(_ptr: *const c_void, _size: u32) -> u32 {
	0
}

#[winfn]
fn OutputDebugStringA(_s: *const u8) {}

#[winfn]
fn GetTickCount() -> u32 {
	let t = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	t.as_millis() as u32
}

#[winfn]
fn GetTickCount64() -> u64 {
	let t = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	t.as_millis() as u64
}

#[winfn]
fn GetProcessTimes(
	_process: *mut c_void,
	creation: *mut u64,
	exit: *mut u64,
	kernel: *mut u64,
	user: *mut u64,
) -> i32 {
	for p in [creation, exit, kernel, user] {
		if !p.is_null() {
			unsafe { p.write(0) };
		}
	}
	1
}

#[winfn]
fn GetThreadTimes(
	_thread: *mut c_void,
	creation: *mut u64,
	exit: *mut u64,
	kernel: *mut u64,
	user: *mut u64,
) -> i32 {
	for p in [creation, exit, kernel, user] {
		if !p.is_null() {
			unsafe { p.write(0) };
		}
	}
	1
}

#[winfn]
fn SetThreadToken(_thread: *mut *mut c_void, _token: *mut c_void) -> i32 {
	1
}

#[winfn]
fn ProcessIdToSessionId(_pid: u32, session: *mut u32) -> i32 {
	if !session.is_null() {
		unsafe { session.write(0) };
	}
	1
}

#[winfn]
fn SetHandleCount(count: u32) -> u32 {
	count
}

#[winfn]
fn LookupPrivilegeValueW(_system: *const u16, _name: *const u16, luid: *mut u64) -> i32 {
	if !luid.is_null() {
		unsafe { luid.write(0) };
	}
	1
}

#[winfn]
fn CoInitializeEx(_reserved: *mut c_void, _coinit: u32) -> u32 {
	0
}

#[winfn]
fn CoUninitialize() {}

#[winfn]
fn CoCreateInstance(
	_clsid: *const c_void,
	_outer: *const c_void,
	_context: u32,
	_iid: *const c_void,
	ppv: *mut *mut c_void,
) -> u32 {
	if !ppv.is_null() {
		unsafe { ppv.write(null_mut()) };
	}
	0x80004002
}

#[winfn]
fn CoSetProxyBlanket(
	_proxy: *mut c_void,
	_authn: u32,
	_authz: u32,
	_server: *const u16,
	_authn_level: u32,
	_imp_level: u32,
	_auth_info: *const c_void,
	_capabilities: u32,
) -> u32 {
	0
}

#[winfn]
fn CoCreateGuid(guid: *mut [u8; 16]) -> u32 {
	if !guid.is_null() {
		rand::fill(unsafe { &mut *guid });
	}
	0
}

#[winfn]
fn IIDFromString(_s: *const u16, iid: *mut [u8; 16]) -> u32 {
	if !iid.is_null() {
		unsafe { (*iid).fill(0) };
	}
	0
}

#[winfn]
fn ExpandEnvironmentStringsW(src: *const u16, dst: *mut u16, size: u32) -> u32 {
	if src.is_null() {
		return 0;
	}
	let s = unsafe { U16CStr::from_ptr_str(src) };
	let len = s.len() + 1;
	if dst.is_null() || size == 0 {
		return len as u32;
	}
	let copy = len.min(size as usize);
	unsafe { dst.copy_from_nonoverlapping(s.as_ptr(), copy) };
	if copy < len {
		unsafe { dst.add(copy - 1).write(0) };
	}
	copy as u32
}

#[winfn]
fn SetEnvironmentVariableW(_name: *const u16, _value: *const u16) -> i32 {
	1
}

#[winfn]
fn RegisterWaitForSingleObject(
	wait_handle: *mut *mut c_void,
	_handle: *mut c_void,
	_callback: *const c_void,
	_context: *mut c_void,
	_timeout: u32,
	_flags: u32,
) -> i32 {
	if !wait_handle.is_null() {
		unsafe { wait_handle.write(dangling_mut()) };
	}
	1
}

#[winfn]
fn InitOnceBeginInitialize(
	atom: &AtomicUsize,
	_flags: u32,
	pending: *mut i32,
	_context: *mut *mut c_void,
) -> i32 {
	let val = atom.load(Ordering::Acquire);
	if val == 2 {
		if !pending.is_null() {
			unsafe { pending.write(0) };
		}
		return 1;
	}
	if atom
		.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
		.is_ok()
	{
		if !pending.is_null() {
			unsafe { pending.write(1) };
		}
		return 1;
	}
	while atom.load(Ordering::Acquire) == 1 {
		spin_loop();
	}
	if !pending.is_null() {
		unsafe { pending.write(0) };
	}
	1
}

#[winfn]
fn InitOnceComplete(atom: &AtomicUsize, _flags: u32, _context: *mut c_void) -> i32 {
	atom.store(2, Ordering::Release);
	1
}

#[winfn]
fn InitOnceExecuteOnce(
	init_once: *mut usize,
	callback: unsafe extern "win64" fn(*mut usize, *mut c_void, *mut *mut c_void) -> i32,
	param: *mut c_void,
	context: *mut *mut c_void,
) -> i32 {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let atom = unsafe { &*(init_once as *const AtomicUsize) };
	if atom.load(Ordering::Acquire) == 2 {
		return 1;
	}
	if atom
		.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
		.is_ok()
	{
		let ret = unsafe { callback(init_once, param, context) };
		atom.store(if ret != 0 { 2 } else { 0 }, Ordering::Release);
		return ret;
	}
	while atom.load(Ordering::Acquire) == 1 {
		spin_loop();
	}
	1
}

#[winfn]
fn GlobalAlloc(flags: u32, size: usize) -> *mut c_void {
	let ptr = unsafe { libc::malloc(size) };
	if flags & 0x40 != 0 && !ptr.is_null() {
		unsafe { ptr::write_bytes(ptr.cast::<u8>(), 0, size) };
	}
	ptr.cast()
}

#[winfn]
fn GlobalFree(mem: *mut c_void) -> *mut c_void {
	unsafe { libc::free(mem) };
	null_mut()
}

#[winfn]
fn LocalAlloc(flags: u32, size: usize) -> *mut c_void {
	GlobalAlloc(flags, size)
}

#[winfn]
fn CreateSemaphoreW(
	_sec: *const c_void,
	_initial: i32,
	_max: i32,
	_name: *const u16,
) -> *mut c_void {
	dangling_mut()
}

#[winfn]
fn CreateMutexW(_sec: *const c_void, _owner: i32, _name: *const u16) -> *mut c_void {
	dangling_mut()
}

#[winfn]
fn OpenProcessToken(_process: *mut c_void, _access: u32, token: *mut *mut c_void) -> i32 {
	if !token.is_null() {
		unsafe { token.write(dangling_mut()) };
	}
	1
}

#[winfn]
fn OpenThreadToken(
	_thread: *mut c_void,
	_access: u32,
	_open_as_self: i32,
	token: *mut *mut c_void,
) -> i32 {
	if !token.is_null() {
		unsafe { token.write(null_mut()) };
	}
	0
}

#[winfn]
fn GetTokenInformation(
	_token: *mut c_void,
	_class: u32,
	_info: *mut c_void,
	_len: u32,
	ret_len: *mut u32,
) -> i32 {
	if !ret_len.is_null() {
		unsafe { ret_len.write(0) };
	}
	0
}

#[winfn]
fn ReleaseMutex(_mutex: *mut c_void) -> i32 {
	1
}

#[winfn]
fn ReleaseSemaphore(_semaphore: *mut c_void, _count: i32, _prev: *mut i32) -> i32 {
	1
}

#[winfn]
fn GlobalReAlloc(mem: *mut c_void, size: usize, _flags: u32) -> *mut c_void {
	unsafe { libc::realloc(mem, size) }
}

#[winfn]
fn AdjustTokenPrivileges(
	_token: *mut c_void,
	_disable_all: i32,
	_new_state: *const c_void,
	_buf_len: u32,
	_prev_state: *mut c_void,
	_ret_len: *mut u32,
) -> i32 {
	1
}

#[winfn]
fn ImpersonateLoggedOnUser(_token: *mut c_void) -> i32 {
	1
}

#[winfn]
fn RevertToSelf() -> i32 {
	1
}

#[winfn]
fn UuidCreate(uuid: *mut [u8; 16]) -> u32 {
	if !uuid.is_null() {
		rand::fill(unsafe { &mut *uuid });
	}
	0
}

#[winfn]
fn OpenSCManagerW(_machine: *const u16, _database: *const u16, _access: u32) -> *mut c_void {
	null_mut()
}

#[winfn]
fn QueryServiceStatus(_service: *mut c_void, _status: *mut c_void) -> i32 {
	0
}

#[winfn]
fn ControlService(_service: *mut c_void, _control: u32, _status: *mut c_void) -> i32 {
	0
}

#[winfn]
fn NotifyServiceStatusChangeW(
	_service: *mut c_void,
	_notify_mask: u32,
	_notify_buffer: *mut c_void,
) -> u32 {
	5
}

#[winfn]
fn GetLengthSid(_sid: *const c_void) -> u32 {
	12
}

#[winfn]
fn CopySid(_len: u32, _dest: *mut c_void, _src: *const c_void) -> i32 {
	0
}

#[winfn]
fn LookupAccountSidW(
	_system: *const u16,
	_sid: *const c_void,
	_name: *mut u16,
	_name_len: *mut u32,
	_domain: *mut u16,
	_domain_len: *mut u32,
	_use: *mut u32,
) -> i32 {
	0
}

#[winfn]
fn DuplicateTokenEx(
	_token: *mut c_void,
	_access: u32,
	_attrs: *const c_void,
	_level: u32,
	_type: u32,
	_new_token: *mut *mut c_void,
) -> i32 {
	0
}

#[winfn]
fn ConvertSidToStringSidA(_sid: *const c_void, _str: *mut *mut u8) -> i32 {
	0
}

#[winfn]
fn RegFlushKey(_key: *mut c_void) -> u32 {
	0
}

#[winfn]
fn RegGetKeySecurity(_key: *mut c_void, _info: u32, _sd: *mut c_void, _len: *mut u32) -> u32 {
	2
}

#[winfn]
fn RegSetKeySecurity(_key: *mut c_void, _info: u32, _sd: *const c_void) -> u32 {
	0
}

#[winfn]
fn CryptEncrypt(
	_key: usize,
	_hash: usize,
	_final: i32,
	_flags: u32,
	_data: *mut u8,
	_data_len: *mut u32,
	_buf_size: u32,
) -> i32 {
	0
}

#[winfn]
fn CryptDecrypt(
	_key: usize,
	_hash: usize,
	_final: i32,
	_flags: u32,
	_data: *mut u8,
	_data_len: *mut u32,
) -> i32 {
	0
}

#[winfn]
fn CryptDeriveKey(_prov: usize, _alg: u32, _hash: usize, _flags: u32, _key: *mut usize) -> i32 {
	0
}

#[winfn]
fn CryptSetKeyParam(_key: usize, _param: u32, _data: *const u8, _flags: u32) -> i32 {
	0
}

#[winfn]
fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
	_str: *const u16,
	_revision: u32,
	sd: *mut *mut c_void,
	_sd_size: *mut u32,
) -> i32 {
	if !sd.is_null() {
		unsafe { sd.write(null_mut()) };
	}
	0
}

#[winfn(alias(ConvertSecurityDescriptorToStringSecurityDescriptorW))]
fn ConvertSecurityDescriptorToStringSecurityDescriptorA(
	_sd: *const c_void,
	_revision: u32,
	_info: u32,
	_str: *mut *mut c_void,
	_str_len: *mut u32,
) -> i32 {
	0
}

#[winfn]
fn GetSecurityDescriptorGroup(
	_sd: *const c_void,
	group: *mut *mut c_void,
	_defaulted: *mut i32,
) -> i32 {
	if !group.is_null() {
		unsafe { group.write(null_mut()) };
	}
	1
}

#[winfn]
fn GetNamedSecurityInfoW(
	_name: *const u16,
	_type: u32,
	_info: u32,
	_owner: *mut *mut c_void,
	_group: *mut *mut c_void,
	_dacl: *mut *mut c_void,
	_sacl: *mut *mut c_void,
	_sd: *mut *mut c_void,
) -> u32 {
	5
}

#[winfn]
fn SetNamedSecurityInfoW(
	_name: *const u16,
	_type: u32,
	_info: u32,
	_owner: *const c_void,
	_group: *const c_void,
	_dacl: *const c_void,
	_sacl: *const c_void,
) -> u32 {
	0
}

#[winfn]
fn ConvertStringSidToSidW(_sid: *const u16, out: *mut *mut c_void) -> i32 {
	if !out.is_null() {
		unsafe { out.write(null_mut()) };
	}
	0
}

#[winfn]
fn AllocateAndInitializeSid(
	_authority: *const c_void,
	_sub_authority_count: u8,
	_a0: u32,
	_a1: u32,
	_a2: u32,
	_a3: u32,
	_a4: u32,
	_a5: u32,
	_a6: u32,
	_a7: u32,
	sid: *mut *mut c_void,
) -> i32 {
	if !sid.is_null() {
		unsafe { sid.write(null_mut()) };
	}
	0
}

#[winfn]
fn FreeSid(_sid: *mut c_void) -> *mut c_void {
	null_mut()
}

#[winfn]
fn CheckTokenMembership(_token: *mut c_void, _sid: *const c_void, is_member: *mut i32) -> i32 {
	if !is_member.is_null() {
		unsafe { is_member.write(0) };
	}
	1
}

#[winfn]
fn CreateProcessW(
	_app: *const u16,
	_cmd: *mut u16,
	_proc_attr: *const c_void,
	_thread_attr: *const c_void,
	_inherit: i32,
	_flags: u32,
	_env: *const c_void,
	_dir: *const u16,
	_si: *const c_void,
	_pi: *mut c_void,
) -> i32 {
	0
}

#[winfn]
fn GetExitCodeProcess(_process: *mut c_void, exit_code: *mut u32) -> i32 {
	if !exit_code.is_null() {
		unsafe { exit_code.write(0) };
	}
	1
}

#[winfn]
fn SleepEx(_ms: u32, _alertable: i32) -> u32 {
	0
}

#[winfn]
fn SetThreadDescription(_thread: *mut c_void, _description: *const u16) -> u32 {
	0
}

#[winfn]
fn IsWow64Process(_process: *mut c_void, wow64: *mut i32) -> i32 {
	if !wow64.is_null() {
		unsafe { wow64.write(0) };
	}
	1
}

#[winfn]
fn GetNativeSystemInfo(info: *mut c_void) {
	if !info.is_null() {
		unsafe { info.write_bytes(0, 48) };
		unsafe { (info as *mut u16).write(9) };
	}
}

#[winfn]
fn OpenProcess(_access: u32, _inherit: i32, _pid: u32) -> *mut c_void {
	null_mut()
}

#[winfn]
fn QueryFullProcessImageNameW(
	_process: *mut c_void,
	_flags: u32,
	name: *mut u16,
	size: *mut u32,
) -> i32 {
	if !name.is_null() && !size.is_null() {
		let s: Vec<u16> = "main.exe\0".encode_utf16().collect();
		let n = s.len().min(unsafe { *size } as usize);
		unsafe { name.copy_from_nonoverlapping(s.as_ptr(), n) };
		unsafe { *size = n as u32 };
	}
	1
}

#[winfn]
fn GetModuleFileNameA(_module: *mut c_void, buf: *mut u8, size: u32) -> u32 {
	if buf.is_null() || size == 0 {
		return 0;
	}
	let s = b"C:\\main.exe\0";
	let n = s.len().min(size as usize);
	unsafe { buf.copy_from_nonoverlapping(s.as_ptr(), n) };
	(n - 1) as u32
}

#[winfn]
fn GetModuleHandleA(_name: *const u8) -> *mut c_void {
	// TODO: Peb
	dangling_mut()
}

#[winfn]
fn ReadProcessMemory(
	_process: *mut c_void,
	_base: *const c_void,
	_buf: *mut c_void,
	_size: usize,
	_read: *mut usize,
) -> i32 {
	0
}

#[winfn]
fn FindFirstVolumeW(name: *mut u16, size: u32) -> *mut c_void {
	let vol: Vec<u16> = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\\0"
		.encode_utf16()
		.collect();
	if !name.is_null() && (size as usize) >= vol.len() {
		unsafe { copy_nonoverlapping(vol.as_ptr(), name, vol.len()) };
	}
	0x7001 as *mut _
}

#[winfn]
fn FindNextVolumeW(_handle: *mut c_void, _name: *mut u16, _size: u32) -> i32 {
	SetLastError(18);
	0
}

#[winfn]
fn FindVolumeClose(_handle: *mut c_void) -> i32 {
	1
}

#[winfn]
fn GetVolumePathNamesForVolumeNameW(
	_name: *const u16,
	paths: *mut u16,
	len: u32,
	ret_len: *mut u32,
) -> i32 {
	let path: Vec<u16> = "C:\\\0\0".encode_utf16().collect();
	if !ret_len.is_null() {
		unsafe { ret_len.write(path.len() as u32) };
	}
	if !paths.is_null() && (len as usize) >= path.len() {
		unsafe { copy_nonoverlapping(path.as_ptr(), paths, path.len()) };
	}
	1
}

#[winfn]
fn GetVolumeInformationW(
	_root: *const u16,
	_name_buf: *mut u16,
	_name_size: u32,
	_serial: *mut u32,
	_max_component: *mut u32,
	_flags: *mut u32,
	_fs_name: *mut u16,
	_fs_size: u32,
) -> i32 {
	0
}

#[winfn]
fn GetComputerNameW(name: *mut u16, size: *mut u32) -> i32 {
	if name.is_null() || size.is_null() {
		return 0;
	}
	let s: Vec<u16> = "CHAMPAGNE\0".encode_utf16().collect();
	let n = s.len().min(unsafe { *size } as usize);
	unsafe { name.copy_from_nonoverlapping(s.as_ptr(), n) };
	unsafe { *size = (n - 1) as u32 };
	1
}

#[winfn]
fn GetConsoleMode(_handle: *mut c_void, _mode: *mut u32) -> i32 {
	0
}

#[winfn]
fn SetConsoleMode(_handle: *mut c_void, _mode: u32) -> i32 {
	0
}

#[winfn]
fn WriteConsoleW(
	_handle: *mut c_void,
	_buf: *const u16,
	len: u32,
	written: *mut u32,
	_reserved: *mut c_void,
) -> i32 {
	if !written.is_null() {
		unsafe { written.write(len) };
	}
	1
}

#[winfn]
fn GetLogicalProcessorInformationEx(_relation: u32, _buf: *mut c_void, ret_len: *mut u32) -> i32 {
	if !ret_len.is_null() {
		unsafe { ret_len.write(0) };
	}
	0
}

#[winfn]
fn GetProcessMitigationPolicy(
	_process: *mut c_void,
	_policy: u32,
	_buf: *mut c_void,
	_len: usize,
) -> i32 {
	0
}
