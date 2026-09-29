#[cfg(not(windows))]
pub mod unix {
	use std::hint::spin_loop;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use champagne_macros::winfn;

	const UNLOCKED: usize = 0;
	const WRITE_LOCKED: usize = 1;

	/// Emulated SRWLock, on windows real should be used.
	///
	/// Contents are considered an implementation detail, and only winapi should be used for it.
	struct VirtualSRWLock {
		val: AtomicUsize,
	}
	impl VirtualSRWLock {
		fn acquire_exclusive(&self) {
			match self.val.compare_exchange_weak(
				UNLOCKED,
				WRITE_LOCKED,
				Ordering::Acquire,
				Ordering::Relaxed,
			) {
				Ok(_) => {}
				Err(_) => spin_loop(),
			}
		}
		fn release_exclusive(&self) {
			self.val.store(UNLOCKED, Ordering::Release);
		}
		fn acquire_shared(&self) {
			loop {
				let current = self.val.load(Ordering::Relaxed);
				if current == WRITE_LOCKED {
					spin_loop();
					continue;
				}
				match self.val.compare_exchange_weak(
					current,
					current + 2,
					Ordering::Acquire,
					Ordering::Relaxed,
				) {
					Ok(_) => return,
					Err(_) => spin_loop(),
				}
			}
		}
		fn release_shared(&self) {
			self.val.fetch_sub(2, Ordering::Release);
		}
		fn try_acquire_exclusive(&self) -> bool {
			self.val
				.compare_exchange(UNLOCKED, WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
				.is_ok()
		}
		fn try_acquire_shared(&self) -> bool {
			let current = self.val.load(Ordering::Relaxed);
			if current == WRITE_LOCKED {
				return false;
			}
			self.val
				.compare_exchange(current, current + 2, Ordering::Acquire, Ordering::Relaxed)
				.is_ok()
		}
	}

	#[winfn]
	fn InitializeSRWLock(srw: *mut VirtualSRWLock) {
		if srw.is_null() {
			return;
		}
		unsafe {
			*srw = VirtualSRWLock {
				val: AtomicUsize::new(UNLOCKED),
			}
		}
	}

	#[winfn]
	fn AcquireSRWLockExclusive(srw: *mut VirtualSRWLock) {
		unsafe {
			(*srw).acquire_exclusive();
		}
	}

	#[winfn]
	fn ReleaseSRWLockExclusive(srw: *mut VirtualSRWLock) {
		unsafe {
			(*srw).release_exclusive();
		}
	}

	#[winfn]
	fn AcquireSRWLockShared(srw: *mut VirtualSRWLock) {
		unsafe { (*srw).acquire_shared() };
	}

	#[winfn]
	fn ReleaseSRWLockShared(srw: *mut VirtualSRWLock) {
		unsafe {
			(*srw).release_shared();
		}
	}

	#[winfn]
	fn TryAcquireSRWLockExclusive(srw: *mut VirtualSRWLock) -> i32 {
		if unsafe { (*srw).try_acquire_exclusive() } {
			1
		} else {
			0
		}
	}

	#[winfn]
	fn TryAcquireSRWLockShared(srw: *mut VirtualSRWLock) -> i32 {
		if unsafe { (*srw).try_acquire_shared() } {
			1
		} else {
			0
		}
	}
}
