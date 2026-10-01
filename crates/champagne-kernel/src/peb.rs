use std::marker::PhantomData;
use std::mem::forget;
use std::pin::Pin;

use crate::assert_offset;
use crate::critical_section::{CriticalSectionGuard, CriticalSectionPtr};
use crate::ldr::{LdrData, LdrDataEntry};
use crate::tib::{TLS_MINIMUM_AVAILABLE, get_tib};

#[repr(C)]
pub struct Peb {
	r1: [u8; 4],
	r2: [*const (); 2],
	ldr: *const LdrData,
	proc_params: *const (),
	subsys_data: *const (),
	process_heap: *const (),
	fast_peb_lock: CriticalSectionPtr,
	atl_thunks_list_ptr: *const (),
	ifeokey: *const (),
	cpflags: u32,
	r3: [u8; 4],
	user_pointer: *const (),
	system_reserved: u32,
	atl_thunk_slist_ptr32: u32,
	api_set_map: *const (),
	tls_expansion_counter: u32,
	r4: [u8; 4],
	tls_bitmap: *const (),
	tls_bitmap_bits: [u32; 2],
	r5: [u8; 0x110 - 0x88],
	loader_lock: CriticalSectionPtr,
}
assert_offset!(Peb, ldr, 0x18);
assert_offset!(Peb, subsys_data, 0x28);
assert_offset!(Peb, fast_peb_lock, 0x38);
assert_offset!(Peb, tls_bitmap_bits, 0x80);
assert_offset!(Peb, loader_lock, 0x110);
unsafe impl Send for Peb {}
unsafe impl Sync for Peb {}
pub trait PebLike {
	fn lock(&self) -> LockedPeb<'_>;
	/// # Safety
	///
	/// Should be balanced with self.unlock_unbalanced()
	unsafe fn lock_unbalanced(&self) {
		forget(self.lock())
	}
	/// # Safety
	///
	/// Should be balanced with self.lock_unbalanced()
	unsafe fn unlock_unbalanced(&self);
	/// # Safety
	///
	/// Peb is unsynchronized
	unsafe fn get_ref(&self) -> PebRef;
	// In windows this is unsynchronized, and thus may cause segfault.
	fn find_entry(&self, entry: &str) -> Option<&LdrDataEntry> {
		unsafe {
			let ldr = (*self.get_ref().0).ldr;
			let pin = Pin::new_unchecked(&*ldr);
			pin.find_lib(entry)
		}
	}
	/// The loader lock the Windows loader itself uses, so DllMain and the TLS
	/// callbacks are serialised against ntdll where ntdll is the one loading.
	fn loader_lock(&self) -> CriticalSectionGuard {
		unsafe { (*self.get_ref().0).loader_lock }.guard()
	}
	/// Snapshots the modules wanting DLL_THREAD_ATTACH/DETACH. Returns owned
	/// pointers rather than borrows so the loader list is not held while guest
	/// code runs, which is free to load further libraries.
	fn thread_notify_list(&self) -> Vec<(*const (), *const ())> {
		unsafe {
			let ldr = (*self.get_ref().0).ldr;
			let pin = Pin::new_unchecked(&*ldr);
			pin.iter()
				.filter(|e| e.wants_thread_calls())
				.map(|e| (e.base(), e.ep()))
				.collect()
		}
	}
	fn disable_thread_calls(&self, base: *const ()) -> bool {
		unsafe {
			let ldr = (*self.get_ref().0).ldr;
			let pin = Pin::new_unchecked(&*ldr);
			let Some(entry) = pin.iter().find(|e| e.base() == base) else {
				return false;
			};
			let entry = (entry as *const LdrDataEntry).cast_mut();
			(*entry).disable_thread_calls();
			true
		}
	}
	// In windows this is unsynchronized, and thus may cause segfault.
	fn find_entry_by_pc(&self, pc: usize) -> Option<&LdrDataEntry> {
		unsafe {
			let ldr = (*self.get_ref().0).ldr;
			let pin = Pin::new_unchecked(&*ldr);
			pin.find_by_pc(pc)
		}
	}
}

pub struct PebRef(pub(crate) *const Peb);
impl PebLike for PebRef {
	fn lock(&self) -> LockedPeb<'_> {
		unsafe { (*self.0).fast_peb_lock }.enter();
		LockedPeb(unsafe { &mut *self.0.cast_mut() }, PhantomData)
	}
	unsafe fn unlock_unbalanced(&self) {
		unsafe { (*self.0).fast_peb_lock.leave() };
	}
	unsafe fn get_ref(&self) -> PebRef {
		PebRef(self.0)
	}
}

pub struct LockedPeb<'p>(*mut Peb, PhantomData<&'p Peb>);
impl LockedPeb<'_> {
	pub fn add_entry(&mut self, entry: Pin<&mut LdrDataEntry>) {
		let ldr = unsafe { Pin::new_unchecked(&mut (*(*self.0).ldr.cast_mut())) };
		ldr.add_entry(entry)
	}
	pub fn add_initialized(&mut self, entry: Pin<&mut LdrDataEntry>) {
		let ldr = unsafe { Pin::new_unchecked(&mut (*(*self.0).ldr.cast_mut())) };
		ldr.add_initialized(entry)
	}
	fn tls_bits(&mut self) -> u64 {
		let bits = unsafe { (*self.0).tls_bitmap_bits };
		bits[0] as u64 | (bits[1] as u64) << 32
	}
	fn set_tls_bits(&mut self, v: u64) {
		unsafe { (*self.0).tls_bitmap_bits = [v as u32, (v >> 32) as u32] };
	}
	pub fn tls_alloc(&mut self) -> Option<u32> {
		let bits = self.tls_bits();
		let index = (!bits).trailing_zeros();
		if index as usize >= TLS_MINIMUM_AVAILABLE {
			return None;
		}
		self.set_tls_bits(bits | 1 << index);
		Some(index)
	}
	pub fn tls_free(&mut self, index: u32) -> bool {
		let bits = self.tls_bits();
		if index as usize >= TLS_MINIMUM_AVAILABLE || bits & 1 << index == 0 {
			return false;
		}
		self.set_tls_bits(bits & !(1 << index));
		true
	}
}
impl Drop for LockedPeb<'_> {
	fn drop(&mut self) {
		unsafe { (*self.0).fast_peb_lock.leave() }
	}
}
#[derive(Clone, Copy)]
pub struct PebHandle(pub(crate) *const Peb);
unsafe impl Send for PebHandle {}
impl PebHandle {
	pub fn to_ref(self) -> PebRef {
		PebRef(self.0)
	}
}

pub fn get_peb() -> PebRef {
	get_tib().get_peb()
}

#[cfg(not(windows))]
pub mod unix {
	use std::cell::UnsafeCell;
	use std::marker::PhantomData;
	use std::mem;
	use std::pin::Pin;

	use moveit::Emplace as _;

	use crate::critical_section::CriticalSectionPtr;
	use crate::ldr::unix::LoaderPrivate;
	use crate::ldr::{LdrData, TlsTemplate};
	use crate::tib::get_tib;

	use super::{LockedPeb, Peb, PebLike, PebRef};

	pub trait PebLikeUnixExt: PebLike {
		fn private(&self) -> &'static crate::ldr::unix::LoaderPrivate {
			use crate::ldr::unix::{LOADER_PRIVATE_MAGIC, LoaderPrivate};

			let private = unsafe { (*self.get_ref().0).subsys_data.cast::<LoaderPrivate>() };
			assert!(!private.is_null(), "peb has no loader private data");
			let private = unsafe { &*private };
			assert_eq!(
				private.magic, LOADER_PRIVATE_MAGIC,
				"peb SubSystemData was overwritten by the guest"
			);
			private
		}
		fn register_tls_template(&self, data: &[u8], zero_fill: usize) -> u32 {
			let private = self.private();
			let mut templates = private.tls_templates.lock();
			let index = templates.len() as u32;
			templates.push(TlsTemplate {
				data: Box::leak(data.to_vec().into_boxed_slice()),
				total_size: data.len() + zero_fill,
			});
			get_tib().materialize_tls(&templates);
			index
		}
		/// Gives the calling thread its own copy of every static TLS block
		/// registered so far. Must run before any guest code on a new thread.
		fn materialize_current_tls(&self) {
			let private = self.private();
			let templates = private.tls_templates.lock();
			get_tib().materialize_tls(&templates);
		}
	}
	impl<T> PebLikeUnixExt for T where T: PebLike {}

	/// PEB emulation, only used on non-windows, in windows real PEB should be used.
	pub struct VirtualPeb(Box<UnsafeCell<Peb>>);
	unsafe impl Sync for VirtualPeb {}
	impl VirtualPeb {
		pub fn new() -> Self {
			let mut peb: Peb = unsafe { mem::zeroed() };
			unsafe {
				peb.ldr = Box::into_raw(Pin::into_inner_unchecked(Box::emplace(LdrData::new())));
			}
			peb.fast_peb_lock = CriticalSectionPtr::unix();
			peb.loader_lock = CriticalSectionPtr::unix();
			// Only sound because this PEB is the loader's own; the real one's
			// SubSystemData belongs to the subsystem DLLs.
			peb.subsys_data = Box::into_raw(Box::new(LoaderPrivate::new())).cast();
			// Slot 0 is reserved, as ntdll does in LdrpInitializeProcess.
			peb.tls_bitmap_bits[0] = 1;

			let boxed = Box::new(UnsafeCell::new(peb));
			Self(boxed)
		}
		pub fn as_ptr(&self) -> *const Peb {
			self.0.as_ref().get()
		}
	}
	impl Default for VirtualPeb {
		fn default() -> Self {
			Self::new()
		}
	}
	impl PebLike for VirtualPeb {
		fn lock(&self) -> LockedPeb<'_> {
			unsafe { (*self.0.get()).fast_peb_lock }.enter();
			LockedPeb(unsafe { &mut *self.0.get() }, PhantomData)
		}
		unsafe fn unlock_unbalanced(&self) {
			unsafe { (*self.0.get()).fast_peb_lock.leave() };
		}
		unsafe fn get_ref(&self) -> PebRef {
			PebRef(self.0.as_ref().get())
		}
	}

	#[test]
	fn require_fn_to_be_send() {
		fn require_send<T: Send>() {}
		require_send::<VirtualPeb>();
	}
}
