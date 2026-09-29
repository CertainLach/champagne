use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use champagne_kernel::critical_section::CriticalSectionPtr;
use champagne_macros::winfn;

struct CondvarSlot {
	condvar: Condvar,
	mutex: Mutex<()>,
}

fn get_or_init(cv: *mut *mut CondvarSlot) -> &'static CondvarSlot {
	let ptr = unsafe { cv.read() };
	if !ptr.is_null() {
		return unsafe { &*ptr };
	}
	let slot = Box::leak(Box::new(CondvarSlot {
		condvar: Condvar::new(),
		mutex: Mutex::new(()),
	}));
	unsafe { cv.write(slot as *mut _) };
	slot
}

#[winfn]
fn InitializeConditionVariable(cv: *mut *mut CondvarSlot) {
	if !cv.is_null() {
		unsafe { cv.write(null_mut()) };
	}
}

#[winfn]
fn SleepConditionVariableCS(
	cv: *mut *mut CondvarSlot,
	cs: CriticalSectionPtr,
	timeout: u32,
) -> i32 {
	let slot = get_or_init(cv);
	unsafe { cs.leave() };
	let guard = slot.mutex.lock().unwrap();
	if timeout == 0xFFFFFFFF {
		let _g = slot.condvar.wait(guard).unwrap();
	} else {
		let _g = slot
			.condvar
			.wait_timeout(guard, Duration::from_millis(timeout as u64))
			.unwrap();
	}
	cs.enter();
	1
}

#[winfn]
fn SleepConditionVariableSRW(
	cv: *mut *mut CondvarSlot,
	_srw: *mut c_void,
	timeout: u32,
	_flags: u32,
) -> i32 {
	let slot = get_or_init(cv);
	let guard = slot.mutex.lock().unwrap();
	if timeout == 0xFFFFFFFF {
		let _g = slot.condvar.wait(guard).unwrap();
	} else {
		let _g = slot
			.condvar
			.wait_timeout(guard, Duration::from_millis(timeout as u64))
			.unwrap();
	}
	1
}

#[winfn]
fn WakeConditionVariable(cv: *mut *mut CondvarSlot) {
	if cv.is_null() {
		return;
	}
	let ptr = unsafe { cv.read() };
	if !ptr.is_null() {
		unsafe { &*ptr }.condvar.notify_one();
	}
}

#[winfn]
fn WakeAllConditionVariable(cv: *mut *mut CondvarSlot) {
	if cv.is_null() {
		return;
	}
	let ptr = unsafe { cv.read() };
	if !ptr.is_null() {
		unsafe { &*ptr }.condvar.notify_all();
	}
}
