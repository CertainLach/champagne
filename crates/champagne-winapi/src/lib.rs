extern crate self as champagne_winapi;

macro_rules! assert_size {
	($ty:ty, $size:expr) => {
		const _: () = assert!(std::mem::size_of::<$ty>() == $size);
	};
}

macro_rules! assert_offset {
	($ty:ty, $field:ident, $offset:expr) => {
		const _: () = assert!(std::mem::offset_of!($ty, $field) == $offset);
	};
}

pub(crate) use assert_offset;
pub(crate) use assert_size;

pub fn to_wide(s: &str) -> Vec<u16> {
	s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub mod app;
pub mod certstore;
pub mod critical_section;
pub mod crt;
pub mod crypto;
pub mod event;
pub mod heap;
pub mod interlocked;
pub mod ldr;
pub mod memory;
pub mod misc;
pub mod net;
pub mod object;
pub mod path;
pub mod peb;
pub mod perf;
pub mod process;
pub mod registry;
pub mod seh;
pub mod slist;
pub mod srw;
pub mod string;
pub mod system;
pub mod thread;
pub mod threadpool;
pub mod time;
pub mod tls;
pub mod version;

pub(crate) mod heap_raw;

#[doc(hidden)]
pub use inventory;
#[doc(hidden)]
pub use tracing::instrument;

pub struct WinFn {
	pub name: &'static str,
	pub ptr: fn() -> usize,
}
inventory::collect!(WinFn);

mod tests {
	// #[repr(C)]
	// struct ThreadProbe {
	// 	errno: usize,
	// 	strlen: usize,
	// 	errno_slot: AtomicUsize,
	// 	tid: AtomicUsize,
	// }
	// fn exercise_threads(data: &LinkerData) -> Result<()> {
	//     let ucrt = data.get("ucrtbase.dll").context("ucrtbase not loaded")?;
	//
	//     let probe = ThreadProbe {
	//         errno: ucrt.exported_fn_raw("_errno")? as usize,
	//         strlen: ucrt.exported_fn_raw("strlen")? as usize,
	//         errno_slot: AtomicUsize::new(0),
	//         tid: AtomicUsize::new(0),
	//     };
	//
	//     extern "win64" fn thread_main(parameter: *mut std::ffi::c_void) -> u32 {
	//         let probe = unsafe { &*parameter.cast::<ThreadProbe>() };
	//         let errno: extern "win64" fn() -> *mut i32 = unsafe { transmute(probe.errno) };
	//         let strlen: extern "win64" fn(*const u8) -> usize = unsafe { transmute(probe.strlen) };
	//
	//         probe.tid.store(get_tib().thread_id() as usize, SeqCst);
	//         probe.errno_slot.store(errno() as usize, SeqCst);
	//         strlen(c"hello from a guest thread".as_ptr().cast()) as u32
	//     }
	//
	//     let main_errno = {
	//         let errno: extern "win64" fn() -> *mut i32 = unsafe { transmute(probe.errno) };
	//         errno() as usize
	//     };
	//
	//     let (handle, reported_tid) = sync::host::create_thread(
	//         thread_main as *mut _,
	//         (&probe as *const ThreadProbe).cast_mut().cast(),
	//     )
	//     .context("CreateThread failed")?;
	//     info!("created thread, handle {handle:?}, reported tid {reported_tid:#x}");
	//
	//     ensure!(
	//         sync::host::wait_for_single_object(handle, 5000) == 0,
	//         "thread did not finish in time"
	//     );
	//     let code = sync::host::exit_code(handle).context("GetExitCodeThread failed")?;
	//     ensure!(code == 25, "unexpected thread exit code {code}");
	//
	//     let thread_errno = probe.errno_slot.load(SeqCst);
	//     let thread_tid = probe.tid.load(SeqCst);
	//     info!(
	//         "main tid {:#x} errno at {main_errno:#x}, guest tid {thread_tid:#x} errno at {thread_errno:#x}",
	//         get_tib().thread_id()
	//     );
	//     ensure!(thread_tid != 0, "guest thread had no thread id");
	//     ensure!(
	//         thread_tid != get_tib().thread_id() as usize,
	//         "guest thread reused the main thread id"
	//     );
	//     ensure!(
	//         thread_tid == reported_tid as usize,
	//         "CreateThread reported tid {reported_tid:#x} but the thread sees {thread_tid:#x}"
	//     );
	//     ensure!(main_errno != 0 && thread_errno != 0, "_errno returned null");
	//     ensure!(
	//         main_errno != thread_errno,
	//         "_errno is shared between threads, per-thread CRT state is not isolated"
	//     );
	//     info!("thread exited with {code}, per-thread CRT state is isolated");
	//
	//     exercise_wait_semantics()?;
	//     Ok(())
	// }
	//
	// fn exercise_wait_semantics() -> Result<()> {
	//     {
	//         // A DllMain may load another library, so the loader lock has to nest on
	//         // the same thread; a plain mutex here would deadlock instead.
	//         let peb = get_tib().get_peb();
	//         let outer = peb.loader_lock();
	//         let inner = peb.loader_lock();
	//         drop(inner);
	//         drop(outer);
	//         info!("loader lock is reentrant");
	//     }
	//
	//     let pseudo = sync::host::current_thread_pseudo();
	//     ensure!(
	//         sync::host::close_handle(pseudo) != 0,
	//         "CloseHandle must accept the current thread pseudo handle"
	//     );
	//
	//     let auto = sync::host::create_event(false, true);
	//     let never = sync::host::create_event(true, false);
	//     ensure!(!auto.is_null() && !never.is_null(), "CreateEvent failed");
	//
	//     // One is signalled, one never will be, so this must time out and leave the
	//     // signalled one alone.
	//     let status = sync::host::wait_multiple(&[auto, never], true, 50);
	//     ensure!(status == 258, "expected WAIT_TIMEOUT, got {status:#x}");
	//     let status = sync::host::wait_multiple(&[auto], false, 0);
	//     ensure!(
	//         status == 0,
	//         "wait-all timeout consumed the auto-reset signal it never reported"
	//     );
	//
	//     sync::host::set_event(never);
	//     let status = sync::host::wait_multiple(&[never], true, 50);
	//     ensure!(status == 0, "expected WAIT_OBJECT_0, got {status:#x}");
	//
	//     let bogus = 0xdead_beefusize as *mut std::ffi::c_void;
	//     let status = sync::host::wait_multiple(&[bogus], false, INFINITE);
	//     ensure!(
	//         status == 0xFFFF_FFFF,
	//         "an invalid handle must fail, not spin forever"
	//     );
	//
	//     info!("wait semantics hold: pseudo handle, wait-all timeout, invalid handle");
	//     Ok(())
	// }
}
