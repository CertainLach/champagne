use std::ffi::c_void;
#[cfg(not(target_os = "windows"))]
use std::mem::forget;
use std::ptr::null_mut;

#[cfg(not(target_os = "windows"))]
use parking_lot::ReentrantMutex;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
	fn EnterCriticalSection(lock: *mut c_void);
	fn LeaveCriticalSection(lock: *mut c_void);
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct CriticalSection(Option<Box<ReentrantMutex<()>>>);
#[cfg(not(target_os = "windows"))]
impl CriticalSection {
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
	/// SAFETY: CS should be entered
	pub unsafe fn leave(&self) {
		unsafe { self.0.as_ref().expect("initialized").force_unlock() }
	}
}
#[cfg(not(target_os = "windows"))]
const _: () = assert!(size_of::<CriticalSection>() == size_of::<usize>());

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct CriticalSectionPtr(*mut c_void);

impl CriticalSectionPtr {
	pub fn null() -> Self {
		Self(null_mut())
	}
	#[cfg(not(windows))]
	pub fn owned() -> Self {
		let lock = Box::into_raw(Box::new(CriticalSection::new()));
		Self(lock.cast())
	}
	pub fn enter(self) {
		assert!(!self.0.is_null(), "critical section is missing");
		#[cfg(windows)]
		unsafe {
			EnterCriticalSection(self.0)
		};
		#[cfg(not(windows))]
		unsafe {
			(*self.0.cast::<CriticalSection>()).enter()
		};
	}
	pub unsafe fn leave(self) {
		#[cfg(windows)]
		unsafe {
			LeaveCriticalSection(self.0)
		};
		#[cfg(not(windows))]
		unsafe {
			(*self.0.cast::<CriticalSection>()).leave()
		};
	}
	pub fn guard(self) -> CriticalSectionGuard {
		self.enter();
		CriticalSectionGuard(self)
	}
	pub unsafe fn from_raw(cs: *mut c_void) -> Self {
		Self(cs)
	}
}

#[must_use]
pub struct CriticalSectionGuard(CriticalSectionPtr);
impl Drop for CriticalSectionGuard {
	fn drop(&mut self) {
		unsafe { self.0.leave() }
	}
}
