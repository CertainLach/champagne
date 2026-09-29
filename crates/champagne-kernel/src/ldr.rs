use derivative::Derivative;
use moveit::{New, new};
use nt_list::NtListElement;
use nt_list::list::{NtList, NtListEntry, NtListHead};
use nt_string::unicode_string::NtUnicodeString;
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr::null;

#[derive(NtList)]
enum InLoad {}
#[derive(NtList)]
enum InMemory {}
#[derive(NtList)]
enum InProgress {}
#[derive(NtList)]
enum Hash {}
#[derive(NtList)]
enum Ddag {}

#[derive(NtListElement, Derivative)]
#[repr(C)]
#[derivative(Default)]
pub struct LdrDataEntry {
	in_load_order: NtListEntry<Self, InLoad>,
	in_memory_order: NtListEntry<Self, InMemory>,
	in_prngress_links: NtListEntry<Self, InProgress>,
	#[derivative(Default(value = "null()"))]
	pub dll_base: *const (),
	#[derivative(Default(value = "null()"))]
	ep: *const (),
	size_of_image: usize,
	full_dll_name: NtUnicodeString,
	base_dll_name: NtUnicodeString,
	flags: u32,
	obsolete_load_count: u16,
	tls_index: u16,
	hash_links: NtListEntry<Self, Hash>,
	time_date_stamp: u32,
	#[derivative(Default(value = "null()"))]
	ep_activation_context: *const (),
	#[derivative(Default(value = "null()"))]
	lock: *const (),
	#[derivative(Default(value = "null()"))]
	ddag_node: *const (),
	node_link: NtListEntry<Self, Ddag>,
	#[derivative(Default(value = "null()"))]
	load_context: *const (),
	#[derivative(Default(value = "null()"))]
	parent_dll_base: *const (),
	#[derivative(Default(value = "null()"))]
	switch_back_context: *const (),
	#[derivative(Default(value = "[null(); 3]"))]
	base_address_index_node: [*const (); 3],
	#[derivative(Default(value = "[null(); 3]"))]
	mapping_info_index_node: [*const (); 3],
	#[derivative(Default(value = "null()"))]
	original_base: *const (),
	load_time: u64,
	base_name_hash_value: u32,
	load_reason: u32,
	implicit_path_options: u32,
	refcnt: u32,
	deploadflags: u32,
	signlevel: u32,
}
/// LDRP_DONT_CALL_FOR_THREADS, as set by DisableThreadLibraryCalls.
const LDRP_DONT_CALL_FOR_THREADS: u32 = 0x0004_0000;

impl LdrDataEntry {
	// TODO: x32 support?
	pub fn base(&self) -> *const () {
		self.dll_base
	}
	pub fn ep(&self) -> *const () {
		self.ep
	}
	pub fn wants_thread_calls(&self) -> bool {
		!self.ep.is_null() && self.flags & LDRP_DONT_CALL_FOR_THREADS == 0
	}
	pub fn disable_thread_calls(&mut self) {
		self.flags |= LDRP_DONT_CALL_FOR_THREADS;
	}
	pub fn size_of_image(&self) -> usize {
		self.size_of_image
	}
	pub fn base_name(&self) -> String {
		self.base_dll_name.to_string()
	}
	pub fn contains_pc(&self, pc: usize) -> bool {
		let base = self.dll_base as usize;
		(base..base + self.size_of_image).contains(&pc)
	}
}

/// Reference counted loader entry reference (currently leaks)
pub struct OwnedLdrData(*mut UnsafeCell<LdrDataEntry>);
impl OwnedLdrData {
	pub fn new(
		full_dll_name: NtUnicodeString,
		base_dll_name: NtUnicodeString,
		dll_base: *const (),
		size_of_image: usize,
		ep: *const (),
	) -> Self {
		let data = LdrDataEntry {
			full_dll_name,
			base_dll_name,
			dll_base,
			size_of_image,
			ep,
			..Default::default()
		};
		let boxed = Box::new(UnsafeCell::new(data));
		Self(Box::into_raw(boxed))
	}
	/// SAFETY: Assuming no threads will alter this entry other than current.
	pub fn unchecked_get_pinned(&mut self) -> Pin<&mut LdrDataEntry> {
		unsafe { Pin::new_unchecked((*self.0).get_mut()) }
	}
}

#[pin_project::pin_project]
#[repr(C)]
#[derive(Derivative)]
#[derivative(Default)]
pub struct LdrData {
	length: u32,
	initialized: u32,
	#[derivative(Default(value = "null()"))]
	ss_handle: *const (),
	#[derivative(Default(value = "MaybeUninit::uninit()"))]
	#[pin]
	in_load_order_module_list: MaybeUninit<NtListHead<LdrDataEntry, InLoad>>,
	#[derivative(Default(value = "MaybeUninit::uninit()"))]
	#[pin]
	in_memory_order_module_list: MaybeUninit<NtListHead<LdrDataEntry, InMemory>>,
	#[derivative(Default(value = "MaybeUninit::uninit()"))]
	#[pin]
	in_initialization_order_module_list: MaybeUninit<NtListHead<LdrDataEntry, InProgress>>,
	#[derivative(Default(value = "null()"))]
	entry_in_progress: *const (),
	shutdown_in_progress: u32,
	#[derivative(Default(value = "null()"))]
	shutdown_thread_id: *const (),
}
impl LdrData {
	pub fn new() -> impl New<Output = Self> {
		new::of(Self::default()).with(|v| {
			let v = v.project();
			{
				let list = NtListHead::new();
				unsafe {
					list.new(v.in_load_order_module_list);
				}
			}
			{
				let list = NtListHead::new();
				unsafe {
					list.new(v.in_memory_order_module_list);
				}
			}
			{
				let list = NtListHead::new();
				unsafe {
					list.new(v.in_initialization_order_module_list);
				}
			}
		})
	}
	pub fn add_entry(self: Pin<&mut Self>, mut e: Pin<&mut LdrDataEntry>) {
		let proj = self.project();
		unsafe {
			proj.in_load_order_module_list
				.map_unchecked_mut(|v| v.assume_init_mut())
				.push_back(e.as_mut().get_unchecked_mut());
			proj.in_initialization_order_module_list
				.map_unchecked_mut(|v| v.assume_init_mut())
				.push_back(e.get_unchecked_mut());
		}
	}
	pub fn add_initialized(self: Pin<&mut Self>, e: Pin<&mut LdrDataEntry>) {
		unsafe {
			self.project()
				.in_initialization_order_module_list
				.map_unchecked_mut(|v| v.assume_init_mut())
				.push_back(e.get_unchecked_mut())
		};
	}
	pub fn find_lib(self: Pin<&Self>, lib: &str) -> Option<&LdrDataEntry> {
		unsafe {
			self.project_ref()
				.in_load_order_module_list
				.map_unchecked(|v| v.assume_init_ref())
				.iter()
		}
		.find(|e| e.base_dll_name == lib)
	}
	pub fn find_by_pc(self: Pin<&Self>, pc: usize) -> Option<&LdrDataEntry> {
		unsafe {
			self.project_ref()
				.in_load_order_module_list
				.map_unchecked(|v| v.assume_init_ref())
				.iter()
		}
		.find(|e| e.contains_pc(pc))
	}
	pub fn iter(self: Pin<&Self>) -> impl Iterator<Item = &LdrDataEntry> {
		unsafe {
			self.project_ref()
				.in_load_order_module_list
				.map_unchecked(|v| v.assume_init_ref())
				.iter()
		}
	}
}

pub struct TlsTemplate {
	pub data: &'static [u8],
	pub total_size: usize,
}

pub mod unix {
	use parking_lot::{Mutex, MutexGuard};
	use std::any::Any;
	use std::collections::HashMap;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

	use crate::object::unix::VirtualObject;

	use super::TlsTemplate;

	pub struct LoaderPrivate {
		pub magic: u64,
		pub tls_templates: Mutex<Vec<TlsTemplate>>,
		objects: Mutex<HashMap<usize, Arc<dyn Any + Send + Sync>>>,
		next_handle: AtomicUsize,
		next_thread_id: AtomicU32,
		tls_callbacks: Mutex<HashMap<usize, Vec<usize>>>,
		wait_all_lock: Mutex<()>,
		slist_lock: Mutex<()>,
	}

	pub const LOADER_PRIVATE_MAGIC: u64 = 0x444C4C4C_4F414452;

	impl LoaderPrivate {
		pub fn new() -> Self {
			Self {
				magic: LOADER_PRIVATE_MAGIC,
				tls_templates: Mutex::new(Vec::new()),
				objects: Mutex::new(HashMap::new()),
				next_handle: AtomicUsize::new(0x1000),
				next_thread_id: AtomicU32::new(0x100),
				tls_callbacks: Mutex::new(HashMap::new()),
				wait_all_lock: Mutex::new(()),
				slist_lock: Mutex::new(()),
			}
		}
		pub fn slist_lock(&self) -> MutexGuard<'_, ()> {
			self.slist_lock.lock()
		}
		pub fn alloc_thread_id(&self) -> u32 {
			// Windows thread ids are multiples of four
			self.next_thread_id.fetch_add(4, Ordering::Relaxed)
		}
		pub fn wait_all_lock(&self) -> MutexGuard<'_, ()> {
			self.wait_all_lock.lock()
		}
		pub fn register_tls_callbacks(&self, base: usize, callbacks: Vec<usize>) {
			self.tls_callbacks.lock().insert(base, callbacks);
		}
		pub fn tls_callbacks_for(&self, base: usize) -> Vec<usize> {
			self.tls_callbacks
				.lock()
				.get(&base)
				.cloned()
				.unwrap_or_default()
		}
		pub fn insert_object_raw(&self, object: Arc<dyn Any + Send + Sync>) -> usize {
			// Windows handles are multiples of four
			let handle = self.next_handle.fetch_add(4, Ordering::Relaxed);
			self.objects.lock().insert(handle, object);
			handle
		}
		pub fn insert_object<T: VirtualObject>(&self, object: Arc<T>) -> usize {
			self.insert_object_raw(object)
		}
		pub fn duplicate_object(&self, handle: usize) -> Option<usize> {
			let object = self.objects.lock().get(&handle).cloned()?;
			Some(self.insert_object_raw(object))
		}
		pub fn get_object<T: VirtualObject>(&self, handle: usize) -> Option<Arc<T>> {
			self.objects.lock().get(&handle).cloned()?.downcast().ok()
		}
		pub fn remove_object(&self, handle: usize) -> bool {
			self.objects.lock().remove(&handle).is_some()
		}
	}
	impl Default for LoaderPrivate {
		fn default() -> Self {
			Self::new()
		}
	}
}
