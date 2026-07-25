use std::ffi::c_void;

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use tracing::{debug, warn};

use crate::winapis::winfn;
use crate::wininternals::{get_tib, PebLike};
use crate::CriticalSection;

const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFFFFFF;
const INFINITE: u32 = 0xFFFFFFFF;

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_SUPPORTED: u32 = 50;

const _: () = assert!(size_of::<CriticalSection>() == size_of::<usize>());

pub struct Event {
    manual_reset: bool,
    signaled: Mutex<bool>,
    changed: Condvar,
}

impl Event {
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
    /// Consumes the signal for auto-reset events, mirroring Windows.
    fn wait(&self, timeout: u32) -> u32 {
        let mut signaled = self.signaled.lock();
        if timeout == INFINITE {
            while !*signaled {
                self.changed.wait(&mut signaled);
            }
        } else {
            let deadline = Instant::now() + Duration::from_millis(timeout as u64);
            while !*signaled {
                if self
                    .changed
                    .wait_until(&mut signaled, deadline)
                    .timed_out()
                    && !*signaled
                {
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

pub enum Object {
    Event(Event),
}

fn insert(object: Object) -> *mut c_void {
    let handle = get_tib().get_peb().private().insert_object(Arc::new(object));
    handle as *mut c_void
}

fn get(handle: *mut c_void) -> Option<Arc<Object>> {
    get_tib()
        .get_peb()
        .private()
        .get_object(handle as usize)?
        .downcast()
        .ok()
}

fn critical_section<'a>(cs: *mut c_void) -> &'a mut CriticalSection {
    unsafe { &mut *cs.cast::<CriticalSection>() }
}

winfn! {
    #[alias("InitializeCriticalSection")]
    fn InitializeCriticalSectionAndSpinCount(cs: *mut c_void, _spin: u32) -> i32 {
        if cs.is_null() {
            return 0;
        }
        unsafe { cs.cast::<CriticalSection>().write(CriticalSection::new()) };
        1
    }

    fn InitializeCriticalSectionEx(cs: *mut c_void, _spin: u32, _flags: u32) -> i32 {
        if cs.is_null() {
            return 0;
        }
        unsafe { cs.cast::<CriticalSection>().write(CriticalSection::new()) };
        1
    }

    fn EnterCriticalSection(cs: *mut c_void) {
        if cs.is_null() {
            return;
        }
        let cs = critical_section(cs);
        if !cs.is_initialized() {
            warn!("entering uninitialized critical section, initializing it");
            cs.init();
        }
        cs.enter();
    }

    fn LeaveCriticalSection(cs: *mut c_void) {
        if cs.is_null() {
            return;
        }
        let cs = critical_section(cs);
        if !cs.is_initialized() {
            warn!("leaving uninitialized critical section");
            return;
        }
        unsafe { cs.leave() };
    }

    fn DeleteCriticalSection(cs: *mut c_void) {
        if cs.is_null() {
            return;
        }
        unsafe { cs.cast::<CriticalSection>().write(CriticalSection(None)) };
    }
}

winfn! {
    #[alias("CreateEventA")]
    fn CreateEventW(
        _attributes: *mut c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> *mut c_void {
        if !name.is_null() {
            warn!("named events are not shared between processes");
        }
        let handle = insert(Object::Event(Event {
            manual_reset: manual_reset != 0,
            signaled: Mutex::new(initial_state != 0),
            changed: Condvar::new(),
        }));
        debug!("created event {handle:?} manual_reset={}", manual_reset != 0);
        handle
    }

    fn SetEvent(handle: *mut c_void) -> i32 {
        match get(handle) {
            Some(object) => {
                let Object::Event(event) = &*object;
                event.set();
                1
            }
            None => {
                warn!("SetEvent on unknown handle {handle:?}");
                get_tib().set_last_error(ERROR_INVALID_HANDLE);
                0
            }
        }
    }

    fn ResetEvent(handle: *mut c_void) -> i32 {
        match get(handle) {
            Some(object) => {
                let Object::Event(event) = &*object;
                event.reset();
                1
            }
            None => {
                warn!("ResetEvent on unknown handle {handle:?}");
                get_tib().set_last_error(ERROR_INVALID_HANDLE);
                0
            }
        }
    }

    fn WaitForSingleObject(handle: *mut c_void, timeout: u32) -> u32 {
        match get(handle) {
            Some(object) => {
                let Object::Event(event) = &*object;
                event.wait(timeout)
            }
            None => {
                warn!("WaitForSingleObject on unknown handle {handle:?}");
                get_tib().set_last_error(ERROR_INVALID_HANDLE);
                WAIT_FAILED
            }
        }
    }

    fn WaitForMultipleObjects(
        count: u32,
        handles: *const *mut c_void,
        wait_all: i32,
        timeout: u32,
    ) -> u32 {
        if handles.is_null() || count == 0 {
            get_tib().set_last_error(ERROR_INVALID_HANDLE);
            return WAIT_FAILED;
        }
        let handles = unsafe { std::slice::from_raw_parts(handles, count as usize) };
        if wait_all != 0 {
            for handle in handles {
                let status = WaitForSingleObject(*handle, timeout);
                if status != WAIT_OBJECT_0 {
                    return status;
                }
            }
            return WAIT_OBJECT_0;
        }
        let deadline = Instant::now() + Duration::from_millis(timeout as u64);
        loop {
            for (i, handle) in handles.iter().enumerate() {
                if WaitForSingleObject(*handle, 0) == WAIT_OBJECT_0 {
                    return WAIT_OBJECT_0 + i as u32;
                }
            }
            if timeout != INFINITE && Instant::now() >= deadline {
                return WAIT_TIMEOUT;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn CloseHandle(handle: *mut c_void) -> i32 {
        if get_tib().get_peb().private().remove_object(handle as usize) {
            return 1;
        }
        match handle as usize {
            1..=3 | usize::MAX => 1,
            _ => {
                warn!("CloseHandle on unknown handle {handle:?}");
                get_tib().set_last_error(ERROR_INVALID_HANDLE);
                0
            }
        }
    }

    fn DuplicateHandle(
        _source_process: *mut c_void,
        source: *mut c_void,
        _target_process: *mut c_void,
        target: *mut *mut c_void,
        _access: u32,
        _inherit: i32,
        _options: u32,
    ) -> i32 {
        if target.is_null() {
            return 0;
        }
        let Some(handle) = get_tib()
            .get_peb()
            .private()
            .duplicate_object(source as usize)
        else {
            warn!("DuplicateHandle on unknown handle {source:?}");
            get_tib().set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        };
        unsafe { target.write(handle as *mut c_void) };
        1
    }

    fn DisableThreadLibraryCalls(_module: *mut c_void) -> i32 {
        1
    }

    fn CreateThread(
        _attributes: *mut c_void,
        _stack_size: usize,
        _start: *mut c_void,
        _parameter: *mut c_void,
        _flags: u32,
        thread_id: *mut u32,
    ) -> *mut c_void {
        warn!("todo: threads: CreateThread refused, caller should fall back to serial execution");
        if !thread_id.is_null() {
            unsafe { thread_id.write(0) };
        }
        get_tib().set_last_error(ERROR_NOT_SUPPORTED);
        std::ptr::null_mut()
    }
}
