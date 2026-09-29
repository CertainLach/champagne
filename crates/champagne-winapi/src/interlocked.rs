use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};

use champagne_macros::winfn;

#[winfn]
fn InterlockedIncrement(dest: *mut i32) -> i32 {
	let atom = unsafe { &*dest.cast::<AtomicI32>() };
	atom.fetch_add(1, Ordering::SeqCst) + 1
}

#[winfn]
fn InterlockedDecrement(dest: *mut i32) -> i32 {
	let atom = unsafe { &*dest.cast::<AtomicI32>() };
	atom.fetch_sub(1, Ordering::SeqCst) - 1
}

#[winfn]
fn InterlockedCompareExchange(dest: *mut i32, exchange: i32, comparand: i32) -> i32 {
	let atom = unsafe { &*dest.cast::<AtomicI32>() };
	match atom.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
		Ok(v) | Err(v) => v,
	}
}

#[winfn]
fn InterlockedExchange(dest: *mut i32, value: i32) -> i32 {
	let atom = unsafe { &*dest.cast::<AtomicI32>() };
	atom.swap(value, Ordering::SeqCst)
}

#[winfn]
fn InterlockedCompareExchange64(dest: *mut i64, exchange: i64, comparand: i64) -> i64 {
	let atom = unsafe { &*dest.cast::<AtomicI64>() };
	match atom.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
		Ok(v) | Err(v) => v,
	}
}
