#[cfg(not(windows))]
pub mod unix {
	use std::ffi::c_void;

	use champagne_kernel::event::unix::{Event, set_event_handle};
	use champagne_macros::winfn;
	use tracing::{debug, warn};

	use crate::peb::{ERROR_INVALID_HANDLE, SetLastError};

	#[winfn(alias(CreateEventA))]
	fn CreateEventW(
		_attributes: *mut c_void,
		manual_reset: i32,
		initial_state: i32,
		name: *const u16,
	) -> *mut c_void {
		if !name.is_null() {
			warn!("named events are not shared between processes");
		}
		let handle = Event::alloc_handle(manual_reset, initial_state);
		debug!(
			"created event {handle:?} manual_reset={}",
			manual_reset != 0
		);
		handle
	}

	#[winfn]
	fn SetEvent(handle: *mut c_void) -> i32 {
		if set_event_handle(handle) {
			1
		} else {
			warn!("SetEvent on unknown handle {handle:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			0
		}
	}

	#[winfn]
	fn ResetEvent(handle: *mut c_void) -> i32 {
		if set_event_handle(handle) {
			1
		} else {
			warn!("ResetEvent on unknown handle {handle:?}");
			SetLastError(ERROR_INVALID_HANDLE);
			0
		}
	}
}
