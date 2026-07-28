use std::cmp::Ordering;
use std::ffi::{CStr, c_char};
use std::slice;

use champagne_macros::winfn;
use tracing::info;

const CSTR_LESS_THAN: i32 = 1;
const CSTR_EQUAL: i32 = 2;
const CSTR_GREATER_THAN: i32 = 3;

use crate::peb::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, SetLastError};

fn mb_input<'a>(src: *const u8, len: i32) -> &'a [u8] {
	unsafe {
		if len < 0 {
			CStr::from_ptr(src.cast()).to_bytes_with_nul()
		} else {
			slice::from_raw_parts(src, len as usize)
		}
	}
}

fn wc_input<'a>(src: *const u16, len: i32) -> &'a [u16] {
	unsafe {
		if len < 0 {
			widestring::U16CStr::from_ptr_str(src).as_slice_with_nul()
		} else {
			slice::from_raw_parts(src, len as usize)
		}
	}
}

fn trim_nul(s: &[u16]) -> &[u16] {
	match s.split_last() {
		Some((0, rest)) => rest,
		_ => s,
	}
}

fn emit<T: Copy>(out: &[T], dst: *mut T, dst_len: i32) -> i32 {
	if dst_len == 0 {
		return out.len() as i32;
	}
	if dst.is_null() || out.len() > dst_len as usize {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	unsafe { dst.copy_from_nonoverlapping(out.as_ptr(), out.len()) };
	out.len() as i32
}
pub const CP_UTF8: u32 = 65001;

#[repr(C)]
struct CpInfo {
	max_char_size: u32,
	default_char: [u8; 2],
	lead_byte: [u8; 12],
}

#[winfn]
fn OutputDebugStringW(s: *const u16) {
	if s.is_null() {
		return;
	}
	let s = unsafe { widestring::U16CStr::from_ptr_str(s) };
	info!("image debug output: {}", s.to_string_lossy());
}

#[winfn]
#[alias(GetOEMCP)]
fn GetACP() -> u32 {
	CP_UTF8
}

#[winfn]
fn GetCPInfo(_cp: u32, info: *mut CpInfo) -> i32 {
	if info.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	unsafe {
		info.write(CpInfo {
			max_char_size: 4,
			default_char: [b'?', 0],
			lead_byte: [0; 12],
		})
	};
	1
}

#[winfn]
fn IsValidCodePage(cp: u32) -> i32 {
	i32::from(cp == CP_UTF8)
}

#[winfn]
fn MultiByteToWideChar(
	_cp: u32,
	_flags: u32,
	src: *const u8,
	src_len: i32,
	dst: *mut u16,
	dst_len: i32,
) -> i32 {
	if src.is_null() || src_len == 0 {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let wide: Vec<u16> = String::from_utf8_lossy(mb_input(src, src_len))
		.encode_utf16()
		.collect();
	emit(&wide, dst, dst_len)
}

#[winfn]
fn WideCharToMultiByte(
	_cp: u32,
	_flags: u32,
	src: *const u16,
	src_len: i32,
	dst: *mut u8,
	dst_len: i32,
	_default_char: *const c_char,
	used_default: *mut i32,
) -> i32 {
	if src.is_null() || src_len == 0 {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if !used_default.is_null() {
		unsafe { used_default.write(0) };
	}
	let narrow = String::from_utf16_lossy(wc_input(src, src_len));
	emit(narrow.as_bytes(), dst, dst_len)
}

const C1_UPPER: u16 = 0x1;
const C1_LOWER: u16 = 0x2;
const C1_DIGIT: u16 = 0x4;
const C1_SPACE: u16 = 0x8;
const C1_PUNCT: u16 = 0x10;
const C1_CNTRL: u16 = 0x20;
const C1_BLANK: u16 = 0x40;
const C1_XDIGIT: u16 = 0x80;
const C1_ALPHA: u16 = 0x100;
const C1_DEFINED: u16 = 0x200;

#[winfn]
fn GetStringTypeW(_info_type: u32, src: *const u16, src_len: i32, out: *mut u16) -> i32 {
	if src.is_null() || out.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let src = wc_input(src, src_len);
	for (i, unit) in src.iter().enumerate() {
		let c = char::from_u32(*unit as u32).unwrap_or('\u{fffd}');
		let mut ty = C1_DEFINED;
		if c.is_uppercase() {
			ty |= C1_UPPER | C1_ALPHA;
		}
		if c.is_lowercase() {
			ty |= C1_LOWER | C1_ALPHA;
		}
		if c.is_alphabetic() {
			ty |= C1_ALPHA;
		}
		if c.is_ascii_digit() {
			ty |= C1_DIGIT;
		}
		if c.is_whitespace() {
			ty |= C1_SPACE;
		}
		if c.is_ascii_punctuation() {
			ty |= C1_PUNCT;
		}
		if c.is_control() {
			ty |= C1_CNTRL;
		}
		if c == ' ' || c == '\t' {
			ty |= C1_BLANK;
		}
		if c.is_ascii_hexdigit() {
			ty |= C1_XDIGIT;
		}
		unsafe { out.add(i).write(ty) };
	}
	1
}

const LCMAP_LOWERCASE: u32 = 0x100;
const LCMAP_UPPERCASE: u32 = 0x200;

#[winfn]
fn LCMapStringW(
	_locale: u32,
	flags: u32,
	src: *const u16,
	src_len: i32,
	dst: *mut u16,
	dst_len: i32,
) -> i32 {
	if src.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let src = String::from_utf16_lossy(wc_input(src, src_len));
	let mapped: Vec<u16> = if flags & LCMAP_UPPERCASE != 0 {
		src.to_uppercase().encode_utf16().collect()
	} else if flags & LCMAP_LOWERCASE != 0 {
		src.to_lowercase().encode_utf16().collect()
	} else {
		src.encode_utf16().collect()
	};
	emit(&mapped, dst, dst_len)
}

const NORM_IGNORECASE: u32 = 0x1;
#[winfn]
fn CompareStringW(
	_locale: u32,
	flags: u32,
	s1: *const u16,
	len1: i32,
	s2: *const u16,
	len2: i32,
) -> i32 {
	if s1.is_null() || s2.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	// wc_input keeps the terminator for a -1 length, which is right for the
	// mapping calls but would make "abc" sort after an explicitly counted
	// "abc" here.
	let a = String::from_utf16_lossy(trim_nul(wc_input(s1, len1)));
	let b = String::from_utf16_lossy(trim_nul(wc_input(s2, len2)));
	let ord = if flags & NORM_IGNORECASE != 0 {
		a.to_lowercase().cmp(&b.to_lowercase())
	} else {
		a.cmp(&b)
	};
	match ord {
		Ordering::Less => CSTR_LESS_THAN,
		Ordering::Equal => CSTR_EQUAL,
		Ordering::Greater => CSTR_GREATER_THAN,
	}
}

const LCID_EN_US: u32 = 0x0409;
const LOCALE_USER_DEFAULT: u32 = 0x0400;
#[winfn]
fn GetUserDefaultLCID() -> u32 {
	LCID_EN_US
}

#[winfn]
fn IsValidLocale(locale: u32, _flags: u32) -> i32 {
	i32::from(locale == LCID_EN_US || locale == LOCALE_USER_DEFAULT)
}
