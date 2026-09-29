use std::ptr;

use champagne_macros::winfn;

const VER_MAJOR: u32 = 10;
const VER_MINOR: u32 = 0;
const VER_BUILD: u32 = 19041;
const VER_PLATFORM_ID: u32 = 2;
const VER_PRODUCT_TYPE: u8 = 0x30;

#[repr(C)]
struct OsVersionInfoExW {
	size: u32,
	major: u32,
	minor: u32,
	build: u32,
	platform_id: u32,
	csd_version: [u16; 128],
	service_pack_major: u16,
	service_pack_minor: u16,
	suite_mask: u16,
	product_type: u8,
	reserved: u8,
}

fn fill_version(info: *mut OsVersionInfoExW) {
	if info.is_null() {
		return;
	}
	let size = unsafe { (*info).size };
	if size == 0 {
		return;
	}
	unsafe {
		(*info).major = VER_MAJOR;
		(*info).minor = VER_MINOR;
		(*info).build = VER_BUILD;
		(*info).platform_id = VER_PLATFORM_ID;
		ptr::write_bytes((*info).csd_version.as_mut_ptr(), 0, 128);
	}
}

#[winfn(alias(GetVersionExA))]
fn GetVersionExW(info: *mut OsVersionInfoExW) -> i32 {
	fill_version(info);
	1
}

#[winfn]
fn GetVersion() -> u32 {
	(VER_MAJOR & 0xFF) | ((VER_MINOR & 0xFF) << 8) | (VER_BUILD << 16)
}

#[winfn]
fn RtlGetVersion(info: *mut OsVersionInfoExW) -> u32 {
	fill_version(info);
	0
}

#[winfn]
fn VerSetConditionMask(mask: u64, _type_mask: u32, _condition: u8) -> u64 {
	mask
}

#[winfn]
fn GetProductInfo(
	_major: u32,
	_minor: u32,
	_sp_major: u32,
	_sp_minor: u32,
	product_type: *mut u32,
) -> i32 {
	if !product_type.is_null() {
		unsafe { product_type.write(VER_PRODUCT_TYPE as u32) };
	}
	1
}
