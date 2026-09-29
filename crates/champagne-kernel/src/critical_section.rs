use std::ffi::c_void;
use std::ptr::null_mut;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
	fn InitializeCriticalSectionAndSpinCount(cs: *mut c_void, _spin: u32) -> i32;
	fn EnterCriticalSection(lock: *mut c_void);
	fn LeaveCriticalSection(lock: *mut c_void);
	fn DeleteCriticalSection(cs: *mut c_void);
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct CriticalSectionPtr(*mut c_void);

impl CriticalSectionPtr {
	pub fn null() -> Self {
		Self(null_mut())
	}
	pub fn init(&mut self, _spin: u32) {
		#[cfg(windows)]
		unsafe {
			InitializeCriticalSectionAndSpinCount(self.0, _spin)
		};
		#[cfg(not(windows))]
		unsafe {
			(self.0.cast::<unix::VirtualCriticalSection>())
				.write(unix::VirtualCriticalSection::new())
		};
	}
	/// # Safety
	///
	/// Should be initialized
	pub unsafe fn delete(&mut self) {
		#[cfg(windows)]
		unsafe {
			DeleteCriticalSection(self.0)
		};
		#[cfg(not(windows))]
		unsafe {
			(self.0.cast::<unix::VirtualCriticalSection>())
				.write(unix::VirtualCriticalSection::null())
		};
	}
	pub fn enter(self) {
		assert!(!self.0.is_null(), "critical section is missing");
		#[cfg(windows)]
		unsafe {
			EnterCriticalSection(self.0)
		};
		#[cfg(not(windows))]
		unsafe {
			(*self.0.cast::<unix::VirtualCriticalSection>()).enter()
		};
	}
	/// # Safety
	///
	/// Should be balanced with self.enter()
	pub unsafe fn leave(self) {
		#[cfg(windows)]
		unsafe {
			LeaveCriticalSection(self.0)
		};
		#[cfg(not(windows))]
		unsafe {
			(*self.0.cast::<unix::VirtualCriticalSection>()).leave()
		};
	}
	pub fn guard(self) -> CriticalSectionGuard {
		self.enter();
		CriticalSectionGuard(self)
	}
	pub fn is_null(&self) -> bool {
		self.0.is_null()
	}
}

#[must_use]
pub struct CriticalSectionGuard(CriticalSectionPtr);
impl Drop for CriticalSectionGuard {
	fn drop(&mut self) {
		unsafe { self.0.leave() }
	}
}

#[cfg(not(windows))]
pub mod unix {
	use parking_lot::ReentrantMutex;
	use std::mem::forget;

	use super::CriticalSectionPtr;
	/// CriticalSection emulation, only used on non-windows, in windows real CriticalSection should be used.
	#[repr(C)]
	pub struct VirtualCriticalSection(Option<Box<ReentrantMutex<()>>>);
	impl VirtualCriticalSection {
		pub fn null() -> Self {
			Self(None)
		}
		pub fn new() -> Self {
			Self(Some(Box::new(ReentrantMutex::new(()))))
		}
		pub fn init(&mut self) {
			self.0 = Some(Box::new(ReentrantMutex::new(())));
		}
		pub fn is_initialized(&self) -> bool {
			self.0.is_some()
		}
		pub fn enter(&self) {
			forget(self.0.as_ref().expect("initialized").lock())
		}
		/// # Safety
		///
		/// CS should be entered
		pub unsafe fn leave(&self) {
			unsafe { self.0.as_ref().expect("initialized").force_unlock() }
		}
	}
	impl Default for VirtualCriticalSection {
		fn default() -> Self {
			Self::new()
		}
	}

	assert_size!(VirtualCriticalSection, size_of::<usize>());

	impl CriticalSectionPtr {
		#[cfg(not(windows))]
		pub fn unix() -> Self {
			let lock = Box::into_raw(Box::new(VirtualCriticalSection::new()));
			Self(lock.cast())
		}
	}
}
