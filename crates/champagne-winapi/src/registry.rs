use std::ffi::c_void;
use std::ptr;

use champagne_macros::winfn;
use tracing::{debug, trace};
use widestring::U16CStr;

use crate::to_wide;

const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_MORE_DATA: u32 = 234;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

struct RegistryKey {
	path: String,
}

enum RegValue {
	Sz(&'static str),
	#[allow(dead_code)]
	Dword(u32),
}

impl RegValue {
	fn encode(&self) -> (u32, Vec<u8>) {
		match self {
			RegValue::Sz(s) => {
				let wide = to_wide(s);
				let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
				(REG_SZ, bytes)
			}
			RegValue::Dword(v) => (REG_DWORD, v.to_le_bytes().to_vec()),
		}
	}
}

fn lookup_value(key_path: &str, value_name: &str) -> Option<RegValue> {
	let key = key_path.to_ascii_lowercase();
	let val = value_name.to_ascii_lowercase();

	match (key.as_str(), val.as_str()) {
		(k, v)
			if k.contains("shell folders") && (v == "common appdata" || v == "commonappdata") =>
		{
			Some(RegValue::Sz("C:\\ProgramData"))
		}
		(k, "appdata") if k.contains("shell folders") => {
			Some(RegValue::Sz("C:\\Users\\user\\AppData\\Roaming"))
		}
		(k, "local appdata") if k.contains("shell folders") => {
			Some(RegValue::Sz("C:\\Users\\user\\AppData\\Local"))
		}
		(k, v) if k.contains("shell folders") && (v == "common desktop" || v == "desktop") => {
			Some(RegValue::Sz("C:\\Users\\user\\Desktop"))
		}
		(k, "personal") if k.contains("shell folders") => {
			Some(RegValue::Sz("C:\\Users\\user\\Documents"))
		}
		(k, "common documents") if k.contains("shell folders") => {
			Some(RegValue::Sz("C:\\Users\\Public\\Documents"))
		}
		(k, v) if k.contains("shell folders") && (v == "common programs" || v == "programs") => {
			Some(RegValue::Sz(
				"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs",
			))
		}
		(k, "programdata") if k.contains("profilelist") => Some(RegValue::Sz("C:\\ProgramData")),
		(k, "profilesdirectory") if k.contains("profilelist") => Some(RegValue::Sz("C:\\Users")),
		(k, "public") if k.contains("profilelist") => Some(RegValue::Sz("C:\\Users\\Public")),
		(k, "programfilesdir") if k.contains("currentversion") && !k.contains("explorer") => {
			Some(RegValue::Sz("C:\\Program Files"))
		}
		(k, "commonfilesdir") if k.contains("currentversion") && !k.contains("explorer") => {
			Some(RegValue::Sz("C:\\Program Files\\Common Files"))
		}
		(k, "programfilesdir (x86)") if k.contains("currentversion") => {
			Some(RegValue::Sz("C:\\Program Files (x86)"))
		}
		(k, "processor_architecture")
			if k.contains("session manager") && k.contains("environment") =>
		{
			Some(RegValue::Sz("AMD64"))
		}
		(k, "number_of_processors")
			if k.contains("session manager") && k.contains("environment") =>
		{
			Some(RegValue::Sz("4"))
		}
		(k, "path") if k.contains("session manager") && k.contains("environment") => {
			Some(RegValue::Sz("C:\\Windows\\system32;C:\\Windows"))
		}
		(k, "temp") if k.contains("session manager") && k.contains("environment") => {
			Some(RegValue::Sz("C:\\Windows\\Temp"))
		}
		(k, "tmp") if k.contains("session manager") && k.contains("environment") => {
			Some(RegValue::Sz("C:\\Windows\\Temp"))
		}
		(k, "os") if k.contains("session manager") && k.contains("environment") => {
			Some(RegValue::Sz("Windows_NT"))
		}
		(k, "systemroot") if k.contains("session manager") && k.contains("environment") => {
			Some(RegValue::Sz("C:\\Windows"))
		}
		(k, "currentbuildnumber") if k.contains("nt") && k.contains("currentversion") => {
			Some(RegValue::Sz("19041"))
		}
		(k, "currentversion") if k.contains("nt") && k.contains("currentversion") => {
			Some(RegValue::Sz("6.3"))
		}
		(k, "productname") if k.contains("nt") && k.contains("currentversion") => {
			Some(RegValue::Sz("Windows 10 Pro"))
		}
		(k, "systemroot") if k.contains("nt") && k.contains("currentversion") => {
			Some(RegValue::Sz("C:\\Windows"))
		}
		_ => None,
	}
}

fn is_predefined_key(key: *mut c_void) -> bool {
	let v = key as usize as u32;
	(0x80000000..=0x80000010).contains(&v)
}

fn key_path_from_handle(key: *mut c_void) -> Option<&'static RegistryKey> {
	if is_predefined_key(key) {
		return None;
	}
	Some(unsafe { &*(key as *const RegistryKey) })
}

fn predefined_name(key: *mut c_void) -> &'static str {
	match key as usize as u32 {
		0x80000000 => "HKCR",
		0x80000001 => "HKCU",
		0x80000002 => "HKLM",
		0x80000003 => "HKU",
		0x80000005 => "HKCC",
		_ => "UNKNOWN",
	}
}

fn make_full_path(parent: *mut c_void, sub_key: &str) -> String {
	let parent_path = if is_predefined_key(parent) {
		predefined_name(parent)
	} else if let Some(pk) = key_path_from_handle(parent) {
		return if sub_key.is_empty() {
			pk.path.clone()
		} else {
			format!("{}\\{}", pk.path, sub_key)
		};
	} else {
		"UNKNOWN"
	};
	if sub_key.is_empty() {
		parent_path.to_string()
	} else {
		format!("{parent_path}\\{sub_key}")
	}
}

#[winfn]
fn RegOpenKeyExW(
	key: *mut c_void,
	sub_key: *const u16,
	_options: u32,
	_access: u32,
	result: *mut *mut c_void,
) -> u32 {
	let name = if !sub_key.is_null() {
		unsafe { U16CStr::from_ptr_str(sub_key) }.to_string_lossy()
	} else {
		String::new()
	};

	let full_path = make_full_path(key, &name);
	trace!(%full_path);

	let rk = Box::new(RegistryKey { path: full_path });
	if !result.is_null() {
		unsafe { result.write(Box::into_raw(rk) as *mut c_void) };
	}
	ERROR_SUCCESS
}

#[winfn]
fn RegCloseKey(key: *mut c_void) -> u32 {
	if key_path_from_handle(key).is_some() {
		let _ = unsafe { Box::from_raw(key as *mut RegistryKey) };
	}
	ERROR_SUCCESS
}

#[winfn]
fn RegQueryValueExW(
	key: *mut c_void,
	name: *const u16,
	_reserved: *mut u32,
	ty: *mut u32,
	data: *mut u8,
	len: *mut u32,
) -> u32 {
	let value_name = if !name.is_null() {
		unsafe { U16CStr::from_ptr_str(name) }.to_string_lossy()
	} else {
		String::new()
	};

	let key_path = if let Some(rk) = key_path_from_handle(key) {
		&rk.path
	} else {
		debug!("no key for {value_name}");
		return ERROR_FILE_NOT_FOUND;
	};

	trace!(%key_path, %value_name);

	let Some(val) = lookup_value(key_path, &value_name) else {
		return ERROR_FILE_NOT_FOUND;
	};

	let (reg_type, encoded) = val.encode();
	let needed = encoded.len() as u32;

	if !ty.is_null() {
		unsafe { ty.write(reg_type) };
	}

	if data.is_null() || len.is_null() {
		if !len.is_null() {
			unsafe { len.write(needed) };
		}
		return ERROR_MORE_DATA;
	}

	let available = unsafe { *len };
	if available < needed {
		unsafe { len.write(needed) };
		return ERROR_MORE_DATA;
	}

	unsafe {
		ptr::copy_nonoverlapping(encoded.as_ptr(), data, encoded.len());
		len.write(needed);
	}
	ERROR_SUCCESS
}

#[winfn]
fn RegCreateKeyExW(
	key: *mut c_void,
	sub_key: *const u16,
	_reserved: u32,
	_class: *const u16,
	_options: u32,
	_access: u32,
	_sec: *const c_void,
	result: *mut *mut c_void,
	disposition: *mut u32,
) -> u32 {
	let name = if !sub_key.is_null() {
		unsafe { U16CStr::from_ptr_str(sub_key) }.to_string_lossy()
	} else {
		String::new()
	};

	let full_path = make_full_path(key, &name);
	trace!(%full_path);

	let rk = Box::new(RegistryKey { path: full_path });
	if !result.is_null() {
		unsafe { result.write(Box::into_raw(rk) as *mut c_void) };
	}
	if !disposition.is_null() {
		unsafe { disposition.write(2) };
	}
	ERROR_SUCCESS
}

#[winfn]
fn RegQueryInfoKeyW(
	_key: *mut c_void,
	_class: *mut u16,
	_class_len: *mut u32,
	_reserved: *mut u32,
	sub_keys: *mut u32,
	_max_sub_key_len: *mut u32,
	_max_class_len: *mut u32,
	values: *mut u32,
	_max_value_name_len: *mut u32,
	_max_value_len: *mut u32,
	_sec_desc_len: *mut u32,
	_last_write_time: *mut u64,
) -> u32 {
	if !sub_keys.is_null() {
		unsafe { sub_keys.write(0) };
	}
	if !values.is_null() {
		unsafe { values.write(0) };
	}
	ERROR_SUCCESS
}

#[winfn]
fn RegSetValueExW(
	_key: *mut c_void,
	_name: *const u16,
	_reserved: u32,
	_ty: u32,
	_data: *const u8,
	_len: u32,
) -> u32 {
	ERROR_SUCCESS
}

#[winfn]
fn RegEnumKeyExW(
	_key: *mut c_void,
	_index: u32,
	_name: *mut u16,
	_name_len: *mut u32,
	_reserved: *mut u32,
	_class: *mut u16,
	_class_len: *mut u32,
	_last_write: *mut u64,
) -> u32 {
	259
}

#[winfn]
fn RegEnumValueW(
	_key: *mut c_void,
	_index: u32,
	_name: *mut u16,
	_name_len: *mut u32,
	_reserved: *mut u32,
	_ty: *mut u32,
	_data: *mut u8,
	_data_len: *mut u32,
) -> u32 {
	259
}

#[winfn]
fn RegDeleteValueW(_key: *mut c_void, _name: *const u16) -> u32 {
	ERROR_FILE_NOT_FOUND
}

#[winfn]
fn RegNotifyChangeKeyValue(
	_key: *mut c_void,
	_watch_subtree: i32,
	_filter: u32,
	_event: *mut c_void,
	_async_flag: i32,
) -> u32 {
	ERROR_SUCCESS
}

#[winfn]
fn RegOpenCurrentUser(_access: u32, result: *mut *mut c_void) -> u32 {
	let rk = Box::new(RegistryKey {
		path: "HKCU".to_string(),
	});
	if !result.is_null() {
		unsafe { result.write(Box::into_raw(rk) as *mut c_void) };
	}
	ERROR_SUCCESS
}
