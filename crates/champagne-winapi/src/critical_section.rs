use std::ffi::c_void;

use champagne_kernel::critical_section::CriticalSection;
use champagne_macros::winfn;
use tracing::warn;

#[winfn]
#[alias(InitializeCriticalSection)]
fn InitializeCriticalSectionAndSpinCount(cs: *mut c_void, _spin: u32) -> i32 {
	if cs.is_null() {
		return 0;
	}
	unsafe { cs.cast::<CriticalSection>().write(CriticalSection::new()) };
	1
}

#[winfn]
fn InitializeCriticalSectionEx(cs: *mut c_void, _spin: u32, _flags: u32) -> i32 {
	if cs.is_null() {
		return 0;
	}
	unsafe { cs.cast::<CriticalSection>().write(CriticalSection::new()) };
	1
}

#[winfn]
fn EnterCriticalSection(cs: *mut c_void) {
	if cs.is_null() {
		return;
	}
	let cs = unsafe { &mut *cs.cast::<CriticalSection>() };
	if !cs.is_initialized() {
		warn!("entering uninitialized critical section, initializing it");
		cs.init();
	}
	cs.enter();
}

#[winfn]
unsafe fn LeaveCriticalSection(cs: *mut c_void) {
	if cs.is_null() {
		return;
	}
	let cs = unsafe { &mut *cs.cast::<CriticalSection>() };
	if !cs.is_initialized() {
		warn!("leaving uninitialized critical section");
		return;
	}
	unsafe { cs.leave() };
}

#[winfn]
unsafe fn DeleteCriticalSection(cs: *mut c_void) {
	if cs.is_null() {
		return;
	}
	drop(unsafe { cs.cast::<CriticalSection>().read() });
	unsafe { cs.cast::<CriticalSection>().write(CriticalSection::null()) };
}
