pub const CURRENT_THREAD_PSEUDO: usize = usize::MAX - 1;
pub const CREATE_SUSPENDED: u32 = 0x0000_0004;

#[cfg(not(windows))]
pub mod unix {
	use std::cell::RefCell;
	use std::ffi::c_void;
	use std::mem::transmute;
	use std::process::exit;
	use std::ptr::null_mut;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::{Duration, Instant};
	use std::{io, thread};

	use parking_lot::{Condvar, Mutex};
	use tracing::{debug, warn};

	use crate::object::unix::Object;
	use crate::object::{INFINITE, WAIT_OBJECT_0, WAIT_TIMEOUT};
	use crate::peb::PebLike as _;
	use crate::peb::unix::{PebLikeUnixExt as _, VirtualPeb};
	use crate::tib::get_tib;
	use crate::tib::unix::{EnteredVirtualTib, VirtualTib};

	use super::CREATE_SUSPENDED;

	thread_local! {
		pub static CURRENT_THREAD: RefCell<Option<Arc<Object>>> = const { RefCell::new(None) };
	}

	type ThreadStart = extern "win64" fn(*mut c_void) -> u32;

	pub struct Thread {
		pub id: u32,
		pub handle: AtomicUsize,
		pub state: Mutex<ThreadState>,
		changed: Condvar,
	}

	pub struct ThreadState {
		pub exit_code: Option<u32>,
		suspended: u32,
	}

	impl Thread {
		pub(crate) fn wait(&self, timeout: u32) -> u32 {
			let mut state = self.state.lock();
			if timeout == INFINITE {
				while state.exit_code.is_none() {
					self.changed.wait(&mut state);
				}
				return WAIT_OBJECT_0;
			}
			let deadline = Instant::now() + Duration::from_millis(timeout as u64);
			while state.exit_code.is_none() {
				if self.changed.wait_until(&mut state, deadline).timed_out()
					&& state.exit_code.is_none()
				{
					return WAIT_TIMEOUT;
				}
			}
			WAIT_OBJECT_0
		}
		pub(crate) fn is_signaled(&self) -> bool {
			self.state.lock().exit_code.is_some()
		}
		pub(crate) fn try_consume(&self) -> bool {
			self.is_signaled()
		}
		fn finish(&self, code: u32) {
			self.state.lock().exit_code = Some(code);
			self.changed.notify_all();
		}
		/// Blocks the calling thread while its own suspend count is above zero.
		fn wait_while_suspended(&self) {
			let mut state = self.state.lock();
			while state.suspended > 0 {
				self.changed.wait(&mut state);
			}
		}
		pub fn resume(&self) -> u32 {
			let mut state = self.state.lock();
			let previous = state.suspended;
			if previous > 0 {
				state.suspended -= 1;
				self.changed.notify_all();
			}
			previous
		}
		pub fn suspend(&self) -> u32 {
			let mut state = self.state.lock();
			let previous = state.suspended;
			state.suspended += 1;
			previous
		}
	}

	fn notify_modules(reason: u32) {
		let peb = get_tib().get_peb();
		let private = peb.private();
		let _loader = peb.loader_lock();

		let mut modules = peb.thread_notify_list();
		if reason == DLL_THREAD_DETACH {
			modules.reverse();
		}
		debug!(
			"notifying {} modules of reason {reason} on thread {:#x}",
			modules.len(),
			get_tib().thread_id()
		);
		for (base, ep) in modules {
			let call_tls = || {
				for callback in private.tls_callbacks_for(base as usize) {
					let callback: extern "win64" fn(*const (), u32, *const c_void) =
						unsafe { transmute(callback) };
					callback(base, reason, null_mut());
				}
			};
			let call_ep = || {
				let ep: extern "win64" fn(*const (), u32, *const c_void) -> i32 =
					unsafe { transmute(ep) };
				ep(base, reason, null_mut());
			};
			// The loader runs initializers before the entry point on the way in and
			// after it on the way out.
			if reason == DLL_THREAD_DETACH {
				call_ep();
				call_tls();
			} else {
				call_tls();
				call_ep();
			}
		}
	}

	pub const DLL_THREAD_ATTACH: u32 = 2;
	pub const DLL_THREAD_DETACH: u32 = 3;

	pub struct HostThread<'peb> {
		tib: VirtualTib<'peb>,
	}
	impl<'peb> HostThread<'peb> {
		pub fn attach(peb: &'peb VirtualPeb) -> Self {
			let tib = VirtualTib::new(peb);
			{
				let _entered = tib.enter();
				get_tib().get_peb().materialize_current_tls();
				notify_modules(DLL_THREAD_ATTACH);
			}
			Self { tib }
		}
		pub fn enter(&self) -> EnteredVirtualTib {
			self.tib.enter()
		}
	}
	impl Drop for HostThread<'_> {
		fn drop(&mut self) {
			let _entered = self.tib.enter();
			notify_modules(DLL_THREAD_DETACH);
		}
	}

	pub struct SpawnedThread {
		pub handle: *mut c_void,
		pub id: u32,
	}

	/// # Safety
	///
	/// start shopuld be a function pointer which accepts parameter idk
	pub unsafe fn spawn_thread(
		start: *mut c_void,
		parameter: *mut c_void,
		stack_size: usize,
		flags: u32,
	) -> io::Result<SpawnedThread> {
		let peb = get_tib().peb_handle();
		let id = peb.to_ref().private().alloc_thread_id();
		let object = Arc::new(Object::Thread(Thread {
			id,
			handle: AtomicUsize::new(0),
			state: Mutex::new(ThreadState {
				exit_code: None,
				suspended: u32::from(flags & CREATE_SUSPENDED != 0),
			}),
			changed: Condvar::new(),
		}));
		let handle = peb.to_ref().private().insert_object(object.clone());
		if let Object::Thread(t) = &*object {
			t.handle.store(handle, Ordering::SeqCst);
		}

		// if !thread_id.is_null() {
		// 	unsafe { thread_id.write(id) };
		// }
		//
		let start = start as usize;
		let parameter = parameter as usize;
		let mut builder = thread::Builder::new().name(format!("guest-{id:#x}"));
		if stack_size != 0 {
			builder = builder.stack_size(stack_size.max(64 * 1024));
		}
		builder.spawn(move || {
			let tib = VirtualTib::for_peb(peb, id);
			let _entered = tib.enter();
			CURRENT_THREAD.with(|current| *current.borrow_mut() = Some(object.clone()));

			let Object::Thread(t) = &*object else {
				unreachable!("just constructed")
			};
			// A CREATE_SUSPENDED thread must execute nothing at all until resumed,
			// loader notifications included.
			t.wait_while_suspended();

			peb.to_ref().materialize_current_tls();
			notify_modules(DLL_THREAD_ATTACH);

			debug!("guest thread {id:#x} starting");
			let start: ThreadStart = unsafe { transmute(start) };
			let code = start(parameter as *mut c_void);
			debug!("guest thread {id:#x} returned {code}");

			notify_modules(DLL_THREAD_DETACH);
			t.finish(code);
		})?;
		Ok(SpawnedThread {
			handle: handle as *mut c_void,
			id,
		})
	}

	pub fn exit_current_thread(code: u32) -> ! {
		let object = CURRENT_THREAD.with(|current| current.borrow().clone());
		let Some(object) = object else {
			warn!("ExitThread on the host thread, exiting the process instead");
			exit(code as i32);
		};
		notify_modules(DLL_THREAD_DETACH);
		let Object::Thread(t) = &*object else {
			unreachable!("only threads are registered here")
		};
		t.finish(code);
		drop(object);

		// FIXME
		unsafe { libc::syscall(libc::SYS_exit, code as i64) };
		unreachable!("thread did not exit")
	}
}
