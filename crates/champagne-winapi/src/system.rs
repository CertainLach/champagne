use std::ffi::c_void;

use champagne_macros::winfn;
use tracing::debug;

use crate::assert_size;

#[repr(C)]
struct SystemInfo {
	processor_architecture: u16,
	reserved: u16,
	page_size: u32,
	minimum_application_address: *mut c_void,
	maximum_application_address: *mut c_void,
	active_processor_mask: usize,
	number_of_processors: u32,
	processor_type: u32,
	allocation_granularity: u32,
	processor_level: u16,
	processor_revision: u16,
}
assert_size!(SystemInfo, 48);

const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

#[winfn]
fn GetSystemInfo(info: *mut SystemInfo) {
	if info.is_null() {
		return;
	}
	unsafe {
		info.write_bytes(0, 1);
		(*info).processor_architecture = PROCESSOR_ARCHITECTURE_AMD64;
		(*info).page_size = 4096;
		(*info).allocation_granularity = 65536;
		(*info).number_of_processors = 1;
		(*info).active_processor_mask = 1;
		(*info).minimum_application_address = 0x10000 as *mut c_void;
		(*info).maximum_application_address = 0x7FFFFFFEFFFF as *mut c_void;
	}
}

#[winfn]
fn IsProcessorFeaturePresent(feature: u32) -> i32 {
	debug!("queried processor feature {feature}");
	0
}

#[winfn]
fn IsDebuggerPresent() -> i32 {
	0
}
