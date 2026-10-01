use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::ptr::write_volatile;
use std::slice;

use crate::ldr::TlsTemplate;
use crate::peb::{Peb, PebHandle, PebRef};

pub const TLS_MINIMUM_AVAILABLE: usize = 64;
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

#[repr(C)]
struct TibNtrnl {
	ex_list: *const (),
	stack_base: *const (),
	stack_limit: *const (),
	sub_system_tib: *const (),
	version: usize,
	user_pointer: *const (),
	this: *const TibNtrnl,
	env: *const (),
	pid: *const (),
	tid: *const (),
	rpc: *const (),
	tls: *const (),
	peb: *const Peb,
	last_error: u32,
	critical_sections: u32,
	reserved: [u8; 0x1480 - 0x70],
	tls_slots: [*mut c_void; TLS_MINIMUM_AVAILABLE],
}
assert_offset!(TibNtrnl, this, 0x30);
assert_offset!(TibNtrnl, peb, 0x60);
assert_offset!(TibNtrnl, tls_slots, 0x1480);

pub struct TibRef(&'static UnsafeCell<TibNtrnl>);
impl TibRef {
	pub fn last_error(&self) -> u32 {
		unsafe { (*self.0.get()).last_error }
	}
	pub fn set_last_error(&self, e: u32) {
		unsafe { write_volatile(&mut (*self.0.get()).last_error, e) }
	}
	pub fn get_peb(&self) -> PebRef {
		PebRef(unsafe { (*self.0.get()).peb })
	}
	pub fn peb_handle(&self) -> PebHandle {
		PebHandle(unsafe { (*self.0.get()).peb })
	}
	pub fn thread_id(&self) -> u32 {
		unsafe { (*self.0.get()).tid as usize as u32 }
	}
	pub fn process_id(&self) -> u32 {
		unsafe { (*self.0.get()).pid as usize as u32 }
	}
	pub(crate) fn materialize_tls(&self, templates: &[TlsTemplate]) {
		let existing = unsafe { (*self.0.get()).tls }.cast::<usize>();
		let existing: &[usize] = if existing.is_null() {
			&[]
		} else {
			unsafe { slice::from_raw_parts(existing, existing.sub(1).read()) }
		};
		let mut array = Vec::with_capacity(templates.len() + 1);
		array.push(templates.len());
		for (index, template) in templates.iter().enumerate() {
			if let Some(&block) = existing.get(index)
				&& block != 0
			{
				array.push(block);
				continue;
			}
			let mut block = vec![0u8; template.total_size].into_boxed_slice();
			block[..template.data.len()].copy_from_slice(template.data);
			array.push(Box::leak(block).as_mut_ptr() as usize);
		}
		let array = Box::leak(array.into_boxed_slice());
		unsafe { (*self.0.get()).tls = array[1..].as_mut_ptr().cast() };
	}
	pub fn tls_get(&self, index: u32) -> Option<*mut c_void> {
		unsafe { (*self.0.get()).tls_slots.get(index as usize).copied() }
	}
	pub fn tls_set(&self, index: u32, value: *mut c_void) -> bool {
		match unsafe { (*self.0.get()).tls_slots.get_mut(index as usize) } {
			Some(slot) => {
				*slot = value;
				true
			}
			None => false,
		}
	}
}

pub fn get_tib() -> TibRef {
	let tib: *const UnsafeCell<TibNtrnl>;
	#[cfg(windows)]
	unsafe {
		asm!("mov {tib}, gs:[0x30]", tib = out(reg) tib)
	};
	#[cfg(not(windows))]
	unsafe {
		use std::arch::asm;

		asm!("rdgsbase {tib}", tib = out(reg) tib)
	};
	assert!(!tib.is_null(), "missing tib");
	TibRef(unsafe { &*tib })
}

#[cfg(not(windows))]
pub mod unix {
	use std::alloc::{Layout, alloc_zeroed};
	use std::arch::asm;
	use std::cell::UnsafeCell;
	use std::marker::PhantomData;
	use std::process;
	use std::ptr::null;

	use crate::peb::PebHandle;
	use crate::peb::unix::{PebLikeUnixExt as _, VirtualPeb};

	use super::TibNtrnl;

	/// TIB emulation, only used on non-windows, in windows real PEB should be used.
	pub struct VirtualTib<'peb>(
		Box<UnsafeCell<TibNtrnl>>,
		PhantomData<(&'peb VirtualPeb, *const ())>,
	);
	impl VirtualTib<'_> {
		pub fn new(peb: &VirtualPeb) -> Self {
			let handle = PebHandle(peb.as_ptr());
			let tid = handle.to_ref().private().alloc_thread_id();
			Self::for_peb(handle, tid)
		}
		pub fn for_peb(peb: PebHandle, tid: u32) -> Self {
			let mut boxed: Box<UnsafeCell<TibNtrnl>> = unsafe {
				let layout = Layout::new::<UnsafeCell<TibNtrnl>>();
				Box::from_raw(alloc_zeroed(layout).cast())
			};
			boxed.get_mut().this = boxed.get();
			boxed.get_mut().tls = null();
			boxed.get_mut().peb = peb.0;
			boxed.get_mut().pid = process::id() as usize as *const ();
			boxed.get_mut().tid = tid as usize as *const ();
			Self(boxed, PhantomData)
		}
		/// SAFETY: Until returned EnteredVirtualTib is dropped, nothing should want data from original tib,
		/// or perform unbalanced (Ie setting, but not restoring) gs segment register access.
		pub fn enter(&self) -> EnteredVirtualTib {
			let prevbase: *const ();
			let gs: *const TibNtrnl = self.0.get();
			unsafe {
				asm!(
					"rdgsbase {prevbase}",
					"wrgsbase {gs}",
					prevbase = out(reg) prevbase,
					gs = in(reg) gs,
				);
			};
			EnteredVirtualTib { prevbase }
		}
	}
	#[must_use]
	pub struct EnteredVirtualTib {
		prevbase: *const (),
	}
	impl Drop for EnteredVirtualTib {
		fn drop(&mut self) {
			unsafe { asm!("wrgsbase {gs}", gs = in(reg) self.prevbase) }
		}
	}
}
