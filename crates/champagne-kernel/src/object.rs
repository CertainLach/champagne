use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::event::Event;
use crate::peb::PebLike as _;
use crate::thread::{CURRENT_THREAD, CURRENT_THREAD_PSEUDO, Thread};
use crate::tib::get_tib;

pub const INFINITE: u32 = 0xFFFFFFFF;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFFFFFF;

pub enum Object {
	Event(Event),
	Thread(Thread),
}

impl Object {
	fn wait(&self, timeout: u32) -> u32 {
		match self {
			Object::Event(event) => event.wait(timeout),
			Object::Thread(thread) => thread.wait(timeout),
		}
	}
	/// Reports the signalled state without consuming it.
	fn is_signaled(&self) -> bool {
		match self {
			Object::Event(event) => event.is_signaled(),
			Object::Thread(thread) => thread.is_signaled(),
		}
	}
	/// Takes the signal, which only auto-reset events actually consume.
	fn try_consume(&self) -> bool {
		match self {
			Object::Event(event) => event.try_consume(),
			Object::Thread(thread) => thread.try_consume(),
		}
	}
}

pub(crate) fn insert_object(object: Object) -> *mut c_void {
	let handle = get_tib()
		.get_peb()
		.private()
		.insert_object(Arc::new(object));
	handle as *mut c_void
}

pub fn get_thread(handle: *mut c_void) -> Option<Arc<Object>> {
	let object = get_object(handle)?;
	matches!(&*object, Object::Thread(_)).then_some(object)
}

pub fn resolve_thread_pseudo(handle: *mut c_void) -> *mut c_void {
	if handle as usize != CURRENT_THREAD_PSEUDO {
		return handle;
	}
	match CURRENT_THREAD.with(|current| current.borrow().clone()) {
		Some(object) => {
			let Object::Thread(t) = &*object else {
				return handle;
			};
			t.handle.load(Ordering::SeqCst) as *mut c_void
		}
		None => handle,
	}
}

pub(crate) fn get_object(handle: *mut c_void) -> Option<Arc<Object>> {
	get_tib()
		.get_peb()
		.private()
		.get_object(handle as usize)?
		.downcast()
		.ok()
}

pub fn wait_object_handle(handle: *mut c_void, timeout: u32) -> Option<u32> {
	Some(get_object(handle)?.wait(timeout))
}
pub fn wait_object_handles(handles: &[*mut c_void], wait_all: i32, timeout: u32) -> Option<u32> {
	let mut objects = Vec::with_capacity(handles.len());
	for handle in handles {
		let object = get_object(*handle)?;
		objects.push(object);
	}

	let deadline = Instant::now() + Duration::from_millis(timeout as u64);
	loop {
		if wait_all != 0 {
			let _all = get_tib().get_peb().private().wait_all_lock();
			if objects.iter().all(|o| o.is_signaled()) {
				for object in &objects {
					object.try_consume();
				}
				return Some(WAIT_OBJECT_0);
			}
		} else {
			for (i, object) in objects.iter().enumerate() {
				if object.try_consume() {
					return Some(WAIT_OBJECT_0 + i as u32);
				}
			}
		}
		if timeout != INFINITE && Instant::now() >= deadline {
			return Some(WAIT_TIMEOUT);
		}
		std::thread::sleep(Duration::from_millis(1));
	}
}
