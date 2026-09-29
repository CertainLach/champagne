use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_macros::winfn;

#[repr(C)]
struct WsaData {
	version: u16,
	high_version: u16,
	max_sockets: u16,
	max_udp_dg: u16,
	vendor_info: *mut u8,
	description: [u8; 257],
	system_status: [u8; 129],
}

#[winfn]
fn WSAStartup(_version: u16, data: *mut WsaData) -> i32 {
	if !data.is_null() {
		unsafe { data.write_bytes(0, 1) };
		unsafe {
			(*data).version = 0x0202;
			(*data).high_version = 0x0202;
		}
	}
	0
}

#[winfn]
fn WSACleanup() -> i32 {
	0
}

#[winfn(no_reset_last_error)]
fn WSAGetLastError() -> i32 {
	0
}

#[winfn(no_reset_last_error)]
fn WSASetLastError(_error: i32) {}

const WSAEINVAL: i32 = 10022;

#[winfn]
fn GetAddrInfoW(
	_node: *const u16,
	_service: *const u16,
	_hints: *const c_void,
	result: *mut *mut c_void,
) -> i32 {
	if !result.is_null() {
		unsafe { result.write(null_mut()) };
	}
	WSAEINVAL
}

#[winfn]
fn FreeAddrInfoW(_info: *mut c_void) {}

#[winfn]
fn getaddrinfo(
	_node: *const u8,
	_service: *const u8,
	_hints: *const c_void,
	result: *mut *mut c_void,
) -> i32 {
	if !result.is_null() {
		unsafe { result.write(null_mut()) };
	}
	WSAEINVAL
}

#[winfn]
fn freeaddrinfo(_info: *mut c_void) {}

#[winfn]
fn socket(_af: i32, _type: i32, _protocol: i32) -> usize {
	usize::MAX
}

#[winfn]
fn closesocket(_s: usize) -> i32 {
	0
}

#[winfn]
fn connect(_s: usize, _addr: *const c_void, _len: i32) -> i32 {
	-1
}

#[winfn]
fn send(_s: usize, _buf: *const u8, _len: i32, _flags: i32) -> i32 {
	-1
}

#[winfn]
fn recv(_s: usize, _buf: *mut u8, _len: i32, _flags: i32) -> i32 {
	-1
}

#[winfn]
fn select(
	_nfds: i32,
	_readfds: *mut c_void,
	_writefds: *mut c_void,
	_exceptfds: *mut c_void,
	_timeout: *const c_void,
) -> i32 {
	-1
}

#[winfn]
fn setsockopt(_s: usize, _level: i32, _name: i32, _val: *const u8, _len: i32) -> i32 {
	0
}

#[winfn]
fn getsockopt(_s: usize, _level: i32, _name: i32, _val: *mut u8, _len: *mut i32) -> i32 {
	-1
}

#[winfn]
fn ioctlsocket(_s: usize, _cmd: i32, _argp: *mut u32) -> i32 {
	0
}

#[winfn]
fn bind(_s: usize, _addr: *const c_void, _len: i32) -> i32 {
	-1
}

#[winfn]
fn listen(_s: usize, _backlog: i32) -> i32 {
	-1
}

#[winfn]
fn accept(_s: usize, _addr: *mut c_void, _len: *mut i32) -> usize {
	usize::MAX
}

#[winfn]
fn shutdown(_s: usize, _how: i32) -> i32 {
	0
}

#[winfn]
fn gethostname(name: *mut u8, len: i32) -> i32 {
	if name.is_null() || len <= 0 {
		return -1;
	}
	let host = b"champagne\0";
	let copy = host.len().min(len as usize);
	unsafe { name.copy_from_nonoverlapping(host.as_ptr(), copy) };
	0
}

#[winfn]
fn htons(hostshort: u16) -> u16 {
	hostshort.to_be()
}

#[winfn]
fn ntohs(netshort: u16) -> u16 {
	u16::from_be(netshort)
}

#[winfn]
fn htonl(hostlong: u32) -> u32 {
	hostlong.to_be()
}

#[winfn]
fn ntohl(netlong: u32) -> u32 {
	u32::from_be(netlong)
}

#[winfn]
fn inet_ntop(_af: i32, _src: *const c_void, _dst: *mut u8, _size: usize) -> *const u8 {
	null_mut()
}

#[winfn]
fn WSASocketW(
	_af: i32,
	_type: i32,
	_protocol: i32,
	_info: *mut c_void,
	_group: u32,
	_flags: u32,
) -> usize {
	usize::MAX
}

#[winfn]
fn WSAIoctl(
	_s: usize,
	_code: u32,
	_in_buf: *const c_void,
	_in_len: u32,
	_out_buf: *mut c_void,
	_out_len: u32,
	bytes_returned: *mut u32,
	_overlapped: *mut c_void,
	_completion: *mut c_void,
) -> i32 {
	if !bytes_returned.is_null() {
		unsafe { bytes_returned.write(0) };
	}
	-1
}

#[winfn]
fn WSAEventSelect(_s: usize, _event: *mut c_void, _events: i32) -> i32 {
	-1
}

#[winfn]
fn WSACreateEvent() -> *mut c_void {
	null_mut()
}

#[winfn]
fn WSACloseEvent(_event: *mut c_void) -> i32 {
	1
}
