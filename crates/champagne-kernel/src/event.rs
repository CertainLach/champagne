use std::ffi::c_void;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use tracing::warn;

use crate::object::{INFINITE, Object, WAIT_OBJECT_0, WAIT_TIMEOUT, get_object, insert_object};

pub struct Event {
	manual_reset: bool,
	signaled: Mutex<bool>,
	changed: Condvar,
}

impl Event {
	pub fn alloc_handle(manual_reset: i32, initial_state: i32) -> *mut c_void {
		insert_object(Object::Event(Self {
			manual_reset: manual_reset != 0,
			signaled: Mutex::new(initial_state != 0),
			changed: Condvar::new(),
		}))
	}

	fn set(&self) {
		*self.signaled.lock() = true;
		if self.manual_reset {
			self.changed.notify_all();
		} else {
			self.changed.notify_one();
		}
	}
	fn reset(&self) {
		*self.signaled.lock() = false;
	}
	pub(crate) fn is_signaled(&self) -> bool {
		*self.signaled.lock()
	}
	/// Takes the signal if there is one, consuming it for auto-reset events.
	pub(crate) fn try_consume(&self) -> bool {
		let mut signaled = self.signaled.lock();
		if !*signaled {
			return false;
		}
		if !self.manual_reset {
			*signaled = false;
		}
		true
	}
	/// Consumes the signal for auto-reset events, mirroring Windows.
	pub(crate) fn wait(&self, timeout: u32) -> u32 {
		let mut signaled = self.signaled.lock();
		if timeout == INFINITE {
			while !*signaled {
				self.changed.wait(&mut signaled);
			}
		} else {
			let deadline = Instant::now() + Duration::from_millis(timeout as u64);
			while !*signaled {
				if self.changed.wait_until(&mut signaled, deadline).timed_out() && !*signaled {
					return WAIT_TIMEOUT;
				}
			}
		}
		if !self.manual_reset {
			*signaled = false;
		}
		WAIT_OBJECT_0
	}
}

pub fn set_event_handle(handle: *mut c_void) -> bool {
	match get_object(handle) {
		Some(object) => {
			let Object::Event(event) = &*object else {
				return false;
			};
			event.set();
			true
		}
		None => false,
	}
}
pub fn reset_event_handle(handle: *mut c_void) -> bool {
	match get_object(handle) {
		Some(object) => {
			let Object::Event(event) = &*object else {
				return false;
			};
			event.reset();
			true
		}
		None => false,
	}
}
