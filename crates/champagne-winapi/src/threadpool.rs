use std::ffi::c_void;

use champagne_macros::winfn;

static FAKE_POOL: u8 = 0;
static FAKE_WORK: u8 = 0;
static FAKE_TIMER: u8 = 0;
static FAKE_WAIT: u8 = 0;
static FAKE_IO: u8 = 0;

fn fake_handle(tag: &'static u8) -> *mut c_void {
	(tag as *const u8 as *mut u8).cast()
}

#[winfn]
fn CreateThreadpool(_reserved: *mut c_void) -> *mut c_void {
	fake_handle(&FAKE_POOL)
}

#[winfn]
fn CloseThreadpool(_pool: *mut c_void) {}

#[winfn]
fn SetThreadpoolThreadMaximum(_pool: *mut c_void, _max: u32) {}

#[winfn]
fn SetThreadpoolThreadMinimum(_pool: *mut c_void, _min: u32) -> i32 {
	1
}

#[winfn]
fn CreateThreadpoolWork(
	_callback: *const c_void,
	_context: *mut c_void,
	_env: *const c_void,
) -> *mut c_void {
	fake_handle(&FAKE_WORK)
}

#[winfn]
fn SubmitThreadpoolWork(_work: *mut c_void) {}

#[winfn]
fn CloseThreadpoolWork(_work: *mut c_void) {}

#[winfn]
fn WaitForThreadpoolWorkCallbacks(_work: *mut c_void, _cancel: i32) {}

#[winfn]
fn CreateThreadpoolTimer(
	_callback: *const c_void,
	_context: *mut c_void,
	_env: *const c_void,
) -> *mut c_void {
	fake_handle(&FAKE_TIMER)
}

#[winfn]
fn SetThreadpoolTimer(_timer: *mut c_void, _due: *const c_void, _period: u32, _window: u32) {}

#[winfn]
fn CloseThreadpoolTimer(_timer: *mut c_void) {}

#[winfn]
fn WaitForThreadpoolTimerCallbacks(_timer: *mut c_void, _cancel: i32) {}

#[winfn]
fn CreateThreadpoolWait(
	_callback: *const c_void,
	_context: *mut c_void,
	_env: *const c_void,
) -> *mut c_void {
	fake_handle(&FAKE_WAIT)
}

#[winfn]
fn SetThreadpoolWait(_wait: *mut c_void, _handle: *mut c_void, _timeout: *const c_void) {}

#[winfn]
fn CloseThreadpoolWait(_wait: *mut c_void) {}

#[winfn]
fn WaitForThreadpoolWaitCallbacks(_wait: *mut c_void, _cancel: i32) {}

#[winfn]
fn CreateThreadpoolIo(
	_file: *mut c_void,
	_callback: *const c_void,
	_context: *mut c_void,
	_env: *const c_void,
) -> *mut c_void {
	fake_handle(&FAKE_IO)
}

#[winfn]
fn StartThreadpoolIo(_io: *mut c_void) {}

#[winfn]
fn CancelThreadpoolIo(_io: *mut c_void) {}

#[winfn]
fn CloseThreadpoolIo(_io: *mut c_void) {}

#[winfn]
fn WaitForThreadpoolIoCallbacks(_io: *mut c_void, _cancel: i32) {}

#[winfn]
fn TrySubmitThreadpoolCallback(
	_callback: *const c_void,
	_context: *mut c_void,
	_env: *const c_void,
) -> i32 {
	1
}

#[winfn]
fn CreateTimerQueueTimer(
	timer: *mut *mut c_void,
	_queue: *mut c_void,
	_callback: *const c_void,
	_param: *mut c_void,
	_due: u32,
	_period: u32,
	_flags: u32,
) -> i32 {
	if !timer.is_null() {
		unsafe { timer.write(fake_handle(&FAKE_TIMER)) };
	}
	1
}
