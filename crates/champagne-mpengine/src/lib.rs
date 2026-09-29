pub mod defender;
pub mod stream;

use std::ffi::c_void;
use std::fs::{self, File};
use std::path::Path;
use std::process::abort;
use std::ptr::null_mut;
use std::{mem, slice};

use champagne::{FinishedPeImage, PeImage, override_import};
use champagne_kernel::peb::PebLike;
use champagne_winapi::certstore::VirtualCertStore;
use champagne_winapi::{self as _, to_wide};
use tracing::{debug, instrument};

use defender::*;
use stream::ScanContext;

pub struct MpEngine {
	_image: FinishedPeImage,
	rsignal: RsignalFn,
	kernel_handle: *mut c_void,
	_cert_store: Box<VirtualCertStore>,
}

impl MpEngine {
	pub fn open(peb: &dyn PebLike, engine_dir: impl AsRef<Path>) -> champagne::Result<Self> {
		let engine_dir = engine_dir.as_ref();
		let dll_path = engine_dir.join("mpengine.dll");

		let mut image = PeImage::open(&dll_path)?;
		image.resolve_imports(override_import, peb)?;
		let finished = image.finish()?;
		#[cfg(not(windows))]
		unsafe {
			finished.init_static_tls()?
		};
		unsafe { finished.call_ep_if_exists()? };

		let rsignal: RsignalFn = unsafe { finished.exported_fn("__rsignal")? };

		let (pe_base, pe_size) = {
			let addr = rsignal as *const () as usize;
			let entry = peb.find_entry_by_pc(addr).unwrap();
			(entry.base() as usize, entry.size_of_image())
		};

		let mut cert_store = Box::new(VirtualCertStore::new());
		extract_vdm_certs(&mut cert_store, engine_dir);
		let engine_data = unsafe { slice::from_raw_parts(pe_base as *const u8, pe_size) };
		cert_store.extract_embedded_certs(engine_data);
		cert_store.sort_self_signed_first();
		cert_store.enter();

		let kernel_handle = boot_engine(rsignal);

		unsafe {
			let kh = kernel_handle as *mut usize;
			let handler_addr = *kh;
			let vtable = Box::into_raw(Box::new(handler_addr));
			*kh = vtable as usize;
		}

		Ok(Self {
			_image: finished,
			rsignal,
			kernel_handle,
			_cert_store: cert_store,
		})
	}

	pub fn scan(&self, path: impl AsRef<Path>) {
		let path = path.as_ref();
		let path_str = path.to_string_lossy();
		let file = match File::open(path) {
			Ok(f) => f,
			Err(e) => {
				tracing::error!("{path_str}: {e}");
				return;
			}
		};
		let name_wide = to_wide(&path_str);

		let mut ctx = ScanContext { file, name_wide };
		let mut descriptor = stream::make_descriptor(&mut ctx);

		let mut scan_reply = ScanReply::new(stream::engine_scan_callback);
		scan_reply.field_c = 0x7fffffff;

		let mut scan_params = ScanStreamParams {
			descriptor: &mut descriptor,
			scan_reply: &mut scan_reply,
			..Default::default()
		};

		let ret = unsafe {
			(self.rsignal)(
				self.kernel_handle,
				RSIG_SCAN_STREAMBUFFER,
				&mut scan_params as *mut _ as *mut c_void,
				mem::size_of::<ScanStreamParams>() as u32,
			)
		};
		if ret != 0 {
			tracing::error!("{path_str}: scan returned {ret:#x}");
		}
	}
}

#[instrument(ret(level = "debug"))]
fn boot_engine(rsignal: RsignalFn) -> *mut c_void {
	let sig_location = to_wide("engine");
	let product_name = to_wide("Legitimate Antivirus");
	let quarantine = to_wide("quarantine");
	let inclusions = to_wide("*.*");

	let mut engine_info = EngineInfo {
		..Default::default()
	};
	let mut engine_config = EngineConfig {
		engine_flags: ENGINE_UNPACK,
		inclusions: inclusions.as_ptr(),
		quarantine_location: quarantine.as_ptr(),
		..Default::default()
	};

	let mut boot_params = BootEngineParams {
		client_version: BOOTENGINE_PARAMS_VERSION,
		signature_location: sig_location.as_ptr(),
		engine_config: &mut engine_config,
		engine_info: &mut engine_info,
		attributes: BOOT_ATTR_NORMAL,
		product_name: product_name.as_ptr(),
		..Default::default()
	};

	let mut kernel_handle: *mut c_void = null_mut();
	let ret = unsafe {
		rsignal(
			&mut kernel_handle as *mut _ as *mut c_void,
			RSIG_BOOTENGINE,
			&mut boot_params as *mut _ as *mut c_void,
			mem::size_of::<BootEngineParams>() as u32,
		)
	};
	if ret != 0 {
		tracing::error!("RSIG_BOOTENGINE failed: {ret:#x}");
		abort();
	}
	kernel_handle
}

#[instrument(skip(store))]
fn extract_vdm_certs(store: &mut VirtualCertStore, engine_dir: &Path) {
	let entries = match fs::read_dir(engine_dir) {
		Ok(e) => e,
		Err(_) => return,
	};
	for entry in entries {
		let Ok(entry) = entry else { continue };
		let path = entry.path();
		let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
		if !name.to_ascii_lowercase().ends_with(".vdm") {
			continue;
		}
		let Ok(data) = fs::read(&path) else {
			continue;
		};
		if data.len() < 0x200 || &data[0..2] != b"MZ" {
			continue;
		}
		let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
		if e_lfanew + 4 + 20 + 240 > data.len() {
			continue;
		}
		let opt_hdr = e_lfanew + 4 + 20;
		let magic = u16::from_le_bytes(data[opt_hdr..opt_hdr + 2].try_into().unwrap());
		let dd_offset = match magic {
			0x10B => opt_hdr + 96,
			0x20B => opt_hdr + 112,
			_ => continue,
		};
		let sec_rva_off = dd_offset + 4 * 8;
		if sec_rva_off + 8 > data.len() {
			continue;
		}
		let sec_offset =
			u32::from_le_bytes(data[sec_rva_off..sec_rva_off + 4].try_into().unwrap()) as usize;
		let sec_size =
			u32::from_le_bytes(data[sec_rva_off + 4..sec_rva_off + 8].try_into().unwrap()) as usize;
		if sec_offset == 0 || sec_size < 8 || sec_offset + sec_size > data.len() {
			continue;
		}
		let win_cert = &data[sec_offset..sec_offset + sec_size];
		let cert_len = u32::from_le_bytes(win_cert[0..4].try_into().unwrap()) as usize;
		if cert_len < 8 || cert_len > sec_size {
			continue;
		}
		let pkcs7 = &win_cert[8..cert_len];
		debug!(
			"extracting certs from {} ({} bytes PKCS7)",
			name,
			pkcs7.len()
		);
		store.extract_pkcs7_certs(pkcs7);
		store.extract_all_certs_from_blob(pkcs7);
		return;
	}
}

#[cfg(target_os = "linux")]
pub fn install_segv_handler() {
	use std::ffi::c_void;

	use nix::libc;
	use nix::sys::signal;

	extern "C" fn handler(sig: i32, _info: *mut libc::siginfo_t, uctx: *mut c_void) {
		let name = match sig {
			libc::SIGSEGV => "SIGSEGV",
			libc::SIGILL => "SIGILL",
			libc::SIGBUS => "SIGBUS",
			_ => "signal",
		};
		if uctx.is_null() {
			tracing::error!("caught {name}, no context");
			abort();
		}
		let uc = uctx.cast::<libc::ucontext_t>();
		let gregs = unsafe { &(*uc).uc_mcontext.gregs };
		let rip = gregs[libc::REG_RIP as usize] as u64;
		let rax = gregs[libc::REG_RAX as usize] as u64;
		let rcx = gregs[libc::REG_RCX as usize] as u64;
		let rdx = gregs[libc::REG_RDX as usize] as u64;
		let rbx = gregs[libc::REG_RBX as usize] as u64;
		let rsp = gregs[libc::REG_RSP as usize] as u64;
		let rbp = gregs[libc::REG_RBP as usize] as u64;
		let rdi = gregs[libc::REG_RDI as usize] as u64;
		let rsi = gregs[libc::REG_RSI as usize] as u64;
		let r8 = gregs[libc::REG_R8 as usize] as u64;
		let r9 = gregs[libc::REG_R9 as usize] as u64;

		if sig == libc::SIGTRAP {
			tracing::error!(
				"TRAP at rip={rip:#x} rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x}"
			);
			let peb = champagne_kernel::peb::get_peb();
			if let Some(entry) = peb.find_entry_by_pc(rip as usize) {
				tracing::error!(
					"  in {}+{:#x}",
					entry.base_name(),
					rip as usize - entry.base() as usize
				);
			}
			for i in 0..6u64 {
				let addr = rsp + (i * 8);
				let val = unsafe { *(addr as *const u64) };
				if let Some(e) = peb.find_entry_by_pc(val as usize) {
					tracing::error!(
						"  [rsp+{:#x}] {}+{:#x}",
						i * 8,
						e.base_name(),
						val as usize - e.base() as usize
					);
				}
			}
			unsafe {
				let gregs = &mut (*uc).uc_mcontext.gregs;
				let ret_addr = *(rsp as *const u64);
				gregs[libc::REG_RIP as usize] = ret_addr as i64;
				gregs[libc::REG_RSP as usize] += 8;
			}
			return;
		}
		tracing::error!("caught {name} at rip={rip:#x}");
		tracing::error!("rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x} rbx={rbx:#x}");
		tracing::error!("rsp={rsp:#x} rbp={rbp:#x} rsi={rsi:#x} rdi={rdi:#x}");
		let r14 = gregs[libc::REG_R14 as usize] as u64;
		let r15 = gregs[libc::REG_R15 as usize] as u64;
		tracing::error!("r8={r8:#x} r9={r9:#x} r14={r14:#x} r15={r15:#x}");

		let peb = champagne_kernel::peb::get_peb();
		if let Some(entry) = peb.find_entry_by_pc(rip as usize) {
			tracing::error!(
				"crash in {}+{:#x}",
				entry.base_name(),
				rip as usize - entry.base() as usize
			);
		} else {
			tracing::error!("crash not in any loaded PE");
		}

		for i in 0..8u64 {
			let addr = rsp + (i * 8);
			let val = unsafe { *(addr as *const u64) };
			let loc = if let Some(e) = peb.find_entry_by_pc(val as usize) {
				format!("{}+{:#x}", e.base_name(), val as usize - e.base() as usize)
			} else {
				String::new()
			};
			tracing::error!("  [rsp+{:#x}] = {val:#x} {loc}", i * 8);
		}
		abort();
	}

	let sa = signal::SigAction::new(
		signal::SigHandler::SigAction(handler),
		signal::SaFlags::SA_SIGINFO,
		signal::SigSet::empty(),
	);
	for sig in [
		signal::Signal::SIGSEGV,
		signal::Signal::SIGILL,
		signal::Signal::SIGBUS,
		signal::Signal::SIGTRAP,
	] {
		unsafe { signal::sigaction(sig, &sa) }.ok();
	}
}
