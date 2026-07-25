use std::alloc::{alloc_zeroed, Layout};
use std::arch::asm;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem;
use std::mem::offset_of;
use std::mem::MaybeUninit;
use std::pin;
use std::pin::pin;
use std::pin::Pin;
use std::ptr::null;
use std::ptr::write_volatile;

use anyhow::bail;
use derivative::Derivative;
use moveit::new::{self, New};
use moveit::Emplace;
use nt_list::list::{NtList, NtListEntry, NtListHead};
use nt_list::NtListElement;
use nt_string::unicode_string::NtUnicodeString;
use pelite::pe64::exports::Export;
use pelite::pe64::exports::GetProcAddress;
use pelite::pe64::Pe;
use pelite::pe64::PeView;
use tracing::debug;
use tracing::trace;

use crate::CriticalSection;

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
    dll_base: *const (),
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
impl LdrDataEntry {
    // TODO: x32 support?
    pub fn pe(&self) -> PeView {
        unsafe { PeView::module(self.dll_base.cast()) }
    }
    pub fn base(&self) -> *const () {
        self.dll_base
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
    pub fn exported_fn_raw(&self, name: &str) -> anyhow::Result<*const ()> {
        trace!("looking up export: {name}");
        let p = self.pe();
        trace!("found pe");
        let init_fn = p.get_export(name)?;
        trace!("export found");
        let init_or = match init_fn {
            Export::Symbol(s) => self.pe().derva::<u8>(*s)?,
            Export::Forward(f) => {
                bail!("expected not forwarded: {f:?}")
            }
        };
        Ok(init_or as *const _ as *const ())
    }
}

/// Reference counted loader entry reference (currently leaks)
pub struct OwnedLdrData(*mut UnsafeCell<LdrDataEntry>);
impl OwnedLdrData {
    pub fn new(
        full_name: NtUnicodeString,
        base_name: NtUnicodeString,
        base: *const (),
        size_of_image: usize,
    ) -> Self {
        let mut data = LdrDataEntry::default();
        data.full_dll_name = full_name;
        data.base_dll_name = base_name;
        data.dll_base = base;
        data.size_of_image = size_of_image;
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
struct LdrData {
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
        .find(|e| e.base_dll_name.to_string() == lib)
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
}

pub const TLS_MINIMUM_AVAILABLE: usize = 64;
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

#[repr(C)]
pub struct Peb {
    r1: [u8; 4],
    r2: [*const (); 2],
    ldr: *const LdrData,
    proc_params: *const (),
    subsys_data: *const (),
    process_heap: *const (),
    fast_peb_lock: *mut CriticalSection,
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
}
const _: () = assert!(offset_of!(Peb, ldr) == 0x18);
const _: () = assert!(offset_of!(Peb, tls_bitmap_bits) == 0x80);
unsafe impl Send for Peb {}
unsafe impl Sync for Peb {}
pub trait PebLike {
    fn lock(&self) -> LockedPeb<'_>;
    /// SAFETY: peb is unsynchronized
    unsafe fn get_ref(&self) -> PebRef;
    // In windows this is unsynchronized, and thus may cause segfault.
    fn find_entry(&self, entry: &str) -> Option<&LdrDataEntry> {
        unsafe {
            let ldr = (*self.get_ref().0).ldr;
            let pin = Pin::new_unchecked(&*ldr);
            pin.find_lib(entry)
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

pub struct VirtualPeb(Box<UnsafeCell<Peb>>);
impl VirtualPeb {
    pub fn new() -> Self {
        let mut peb: Peb = unsafe { mem::zeroed() };
        unsafe {
            peb.ldr = Box::into_raw(Pin::into_inner_unchecked(Box::emplace(LdrData::new())));
            peb.fast_peb_lock = Box::into_raw(Box::new(mem::zeroed()));

            (*peb.fast_peb_lock).init();
        }

        let boxed = Box::new(UnsafeCell::new(peb));
        Self(boxed)
    }
    pub fn as_ptr(&self) -> *const Peb {
        self.0.as_ref().get()
    }
}
impl PebLike for VirtualPeb {
    fn lock(&self) -> LockedPeb {
        unsafe { (*(*self.0.get()).fast_peb_lock).enter() };
        LockedPeb(unsafe { &mut *self.0.get() }, PhantomData)
    }
    unsafe fn get_ref(&self) -> PebRef {
        PebRef(self.0.as_ref().get())
    }
}
pub struct PebRef(*const Peb);
impl PebLike for PebRef {
    fn lock(&self) -> LockedPeb {
        unsafe { (*(*self.0).fast_peb_lock).enter() };
        LockedPeb(unsafe { &mut *self.0.cast_mut() }, PhantomData)
    }
    unsafe fn get_ref(&self) -> PebRef {
        PebRef(self.0)
    }
}

/// Only one thread may have locked peb at a time, however, it can have multiple instances of it.
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
        unsafe { (*(*self.0).fast_peb_lock).leave() }
    }
}

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
const _: () = assert!(offset_of!(TibNtrnl, peb) == 0x60);
const _: () = assert!(offset_of!(TibNtrnl, tls_slots) == 0x1480);
pub struct VirtualTib<'peb>(
    Box<UnsafeCell<TibNtrnl>>,
    PhantomData<(&'peb VirtualPeb, *const ())>,
);
impl VirtualTib<'_> {
    pub fn new(peb: &VirtualPeb) -> Self {
        // Is POD, allocated zeroed to keep the full TEB off the stack
        let mut boxed: Box<UnsafeCell<TibNtrnl>> = unsafe {
            let layout = Layout::new::<UnsafeCell<TibNtrnl>>();
            Box::from_raw(alloc_zeroed(layout).cast())
        };
        boxed.get_mut().this = boxed.get();
        boxed.get_mut().tls = 0xfafafafausize as *const ();
        boxed.get_mut().peb = peb.as_ptr();
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

#[must_use]
pub struct EnteredVirtualTib {
    prevbase: *const (),
}
impl Drop for EnteredVirtualTib {
    fn drop(&mut self) {
        unsafe { asm!("wrgsbase {gs}", gs = in(reg) self.prevbase) }
    }
}

pub fn get_tib() -> TibRef {
    let tib: *const UnsafeCell<_>;
    unsafe { asm!("rdgsbase {tib}", tib = out(reg) tib) };
    assert!(!tib.is_null(), "missing tib");
    TibRef(unsafe { &*tib })
}

#[test]
fn require_fn_to_be_send() {
    fn require_send<T: Send>() {}
    require_send::<VirtualPeb>();
}
