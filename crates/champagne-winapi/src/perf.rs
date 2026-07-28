use std::sync::OnceLock;
use std::thread::{park, sleep, yield_now};
use std::time::{Duration, Instant};

use champagne_kernel::object::INFINITE;
use champagne_macros::winfn;

#[winfn]
fn QueryPerformanceCounter(out: *mut u64) -> i32 {
	if out.is_null() {
		return 0;
	}
	static START: OnceLock<Instant> = OnceLock::new();
	let elapsed = START.get_or_init(Instant::now).elapsed();
	unsafe { out.write_unaligned(elapsed.as_nanos() as u64 / 100) };
	1
}

#[winfn]
fn QueryPerformanceFrequency(out: *mut u64) -> i32 {
	if out.is_null() {
		return 0;
	}
	unsafe { out.write_unaligned(10_000_000) };
	1
}

#[winfn]
fn Sleep(ms: u32) {
	match ms {
		0 => yield_now(),
		INFINITE => loop {
			park()
		},
		ms => sleep(Duration::from_millis(ms as u64)),
	}
}
