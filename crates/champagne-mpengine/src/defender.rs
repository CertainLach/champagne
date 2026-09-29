use std::ffi::c_void;
use std::mem;

pub const RSIG_BOOTENGINE: u32 = 0x4036;
pub const RSIG_SCAN_STREAMBUFFER: u32 = 0x403D;

pub const BOOTENGINE_PARAMS_VERSION: u32 = 0x8E00;
pub const BOOT_ATTR_NORMAL: u32 = 1;
pub const ENGINE_UNPACK: u32 = 1 << 1;

pub const SCAN_FILENAME: u32 = 1 << 8;
pub const SCAN_ENCRYPTED: u32 = 1 << 6;
pub const SCAN_MEMBERNAME: u32 = 1 << 7;
pub const SCAN_FILETYPE: u32 = 1 << 9;
pub const SCAN_PACKERSTART: u32 = 1 << 19;
#[allow(dead_code)]
pub const SCAN_PACKEREND: u32 = 1 << 12;
pub const SCAN_CORRUPT: u32 = 1 << 13;
#[allow(dead_code)]
pub const SCAN_VIRUSFOUND: u32 = 1 << 27;

pub type RsignalFn = unsafe extern "win64" fn(*mut c_void, u32, *mut c_void, u32) -> u32;

#[repr(C, packed)]
pub struct EngineInfo {
	pub field_0: u32,
	pub field_4: u32,
	pub field_8: u32,
	pub field_c: u32,
}

#[repr(C)]
pub struct EngineConfig {
	pub engine_flags: u32,
	pub inclusions: *const u16,
	pub exceptions: *const c_void,
	pub unknown_string_2: *const u16,
	pub quarantine_location: *const u16,
	pub field_14: u32,
	pub field_18: u32,
	pub field_1c: u32,
	pub field_20: u32,
	pub field_24: u32,
	pub field_28: u32,
	pub field_2c: u32,
	pub field_30: u32,
	pub field_34: u32,
	pub unknown_ansi_string_1: *const u8,
	pub unknown_ansi_string_2: *const u8,
	pub unknown_ansi_string_3: *const u8,
}

#[repr(C)]
pub struct BootEngineParams {
	pub client_version: u32,
	pub signature_location: *const u16,
	pub spynet_source: *const c_void,
	pub engine_config: *mut EngineConfig,
	pub engine_info: *mut EngineInfo,
	pub scan_report_location: *const u16,
	pub boot_flags: u32,
	pub local_copy_directory: *const u16,
	pub offline_target_os: *const u16,
	pub product_string: [u8; 16],
	pub field_34: u32,
	pub global_callback: *const c_void,
	pub engine_context: *const c_void,
	pub avg_cpu_load_factor: u32,
	pub field_44: [u8; 16],
	pub spynet_reporting_guid: *const u16,
	pub spynet_version: *const u16,
	pub nis_engine_version: *const u16,
	pub nis_signature_version: *const u16,
	pub flighting_enabled: u32,
	pub flighting_level: u32,
	pub dynamic_config: *const c_void,
	pub auto_sample_submission: u32,
	pub enable_threat_logging: u32,
	pub product_name: *const u16,
	pub passive_mode: u32,
	pub sense_enabled: u32,
	pub sense_org_id: *const u16,
	pub attributes: u32,
	pub block_at_first_seen: u32,
	pub pua_protection: u32,
	pub side_by_side_passive_mode: u32,
}

#[repr(C)]
pub struct StreamBufferDescriptor {
	pub user_ptr: *mut c_void,
	pub read: unsafe extern "win64" fn(*mut c_void, u64, *mut c_void, u32, *mut u32) -> u32,
	pub write: unsafe extern "win64" fn(*mut c_void, u64, *const c_void, u32, *mut u32) -> u32,
	pub get_size: unsafe extern "win64" fn(*mut c_void, *mut u64) -> u32,
	pub set_size: unsafe extern "win64" fn(*mut c_void, *mut u64) -> u32,
	pub get_name: unsafe extern "win64" fn(*mut c_void) -> *const u16,
	pub set_attributes: unsafe extern "win64" fn(*mut c_void, u32, *const c_void, u32) -> u32,
	pub get_attributes:
		unsafe extern "win64" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> u32,
}

#[repr(C)]
pub struct ScanStreamParams {
	pub descriptor: *mut StreamBufferDescriptor,
	pub scan_reply: *mut ScanReply,
	pub unknown_b: u32,
	pub unknown_c: u32,
	pub unknown_d: u64,
}

#[repr(C)]
pub struct ScanReply {
	pub engine_scan_callback: unsafe extern "win64" fn(*mut ScanStruct) -> u32,
	pub field_4: u32,
	pub field_8: u32,
	pub field_c: u32,
}

#[repr(C)]
pub struct ScanStruct {
	pub field_0: u32,
	pub flags: u32,
	pub file_name: *const u8,
	pub virus_name: [u8; 28],
	pub field_28: u32,
	pub field_2c: u32,
	pub field_30: u32,
	pub field_34: u32,
	pub field_38: u32,
	pub field_3c: u32,
	pub field_40: u32,
	pub field_44: u32,
	pub field_48: u32,
	pub field_4c: u32,
	pub file_size: u32,
	pub field_54: u32,
	pub user_ptr: u32,
	pub field_5c: u32,
	pub maybe_filename_2: *const u8,
	pub stream_name_1: *const u16,
	pub stream_name_2: *const u16,
	pub field_6c: u32,
	pub threat_id: u32,
}

impl Default for BootEngineParams {
	fn default() -> Self {
		unsafe { mem::zeroed() }
	}
}

impl Default for EngineConfig {
	fn default() -> Self {
		unsafe { mem::zeroed() }
	}
}

impl Default for EngineInfo {
	fn default() -> Self {
		unsafe { mem::zeroed() }
	}
}

impl ScanReply {
	pub fn new(callback: unsafe extern "win64" fn(*mut ScanStruct) -> u32) -> Self {
		Self {
			engine_scan_callback: callback,
			field_4: 0,
			field_8: 0,
			field_c: 0,
		}
	}
}

impl Default for ScanStreamParams {
	fn default() -> Self {
		unsafe { mem::zeroed() }
	}
}
