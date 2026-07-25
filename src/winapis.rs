use std::ffi::{c_char, c_void, CStr};
use std::ptr::{null, null_mut};
use tracing::{debug, info, warn};

use crate::wininternals::{get_tib, PebLike, TLS_OUT_OF_INDEXES};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;

static PROCESS_HEAP: u8 = 0;

fn process_heap() -> *mut c_void {
    (&raw const PROCESS_HEAP).cast_mut().cast()
}

pub fn override_import(_module: &str, name: &str) -> Option<usize> {
    Some(match name {
        "malloc" => {
            extern "win64" fn my_malloc(size: usize) -> *mut c_void {
                dbg!(size);
                unsafe { libc::malloc(size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_malloc as usize
        }
        "calloc" => {
            extern "win64" fn my_malloc(nobj: usize, size: usize) -> *mut c_void {
                dbg!(nobj, size);
                unsafe { libc::calloc(nobj, size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_malloc as usize
        }
        "free" => {
            extern "win64" fn my_free(size: *mut c_void) {
                dbg!(size);
                unsafe { libc::free(size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_free as usize
        }
        "memset" => {
            extern "win64" fn my_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
                dbg!(dst, c, n);
                unsafe { libc::memset(dst, c, n) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_memset as usize
            // fuckup_cc("memset", libc::memset as unsafe extern "C" fn(_, _, _) -> _)
        }
        "memcpy" => {
            extern "win64" fn my_memcpy(
                dst: *mut c_void,
                c: *const c_void,
                n: usize,
            ) -> *mut c_void {
                unsafe { libc::memcpy(dst, c, n) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_memcpy as usize
            // fuckup_cc("memcpy", libc::memcpy as unsafe extern "C" fn(_, _, _) -> _)
        }
        // "getenv" => fuckup_cc("getenv", libc::getenv as unsafe extern "C" fn(_) -> _),
        // "GetModuleHandleW" => {
        //     extern "win64" fn find_module(name: *const ()) -> *const c_void {
        //         dbg!(name);
        //         null()
        //     }
        //     find_module as usize
        // }
        // "GetModuleHandleA" => {
        //     extern "win64" fn find_module(name: *const c_char) -> *const c_void {
        //         let name = unsafe { CStr::from_ptr(name) };
        //         dbg!(name);
        //         null()
        //     }
        //     find_module as usize
        // }
        // "GetProcAddress" => {
        //     extern "win64" fn find_proc(handle: *const (), name: *const c_char) -> *const c_void {
        //         let name = unsafe { CStr::from_ptr(name) };
        //         dbg!(handle, name);
        //         null()
        //     }
        //     find_proc as usize
        // }
        "GetProcessHeap" => {
            extern "win64" fn get_process_heap() -> *mut c_void {
                process_heap()
            }
            get_process_heap as usize
        }
        "HeapAlloc" => {
            extern "win64" fn heap_alloc(_heap: *mut c_void, flags: u32, size: usize) -> *mut c_void {
                unsafe {
                    if flags & HEAP_ZERO_MEMORY != 0 {
                        libc::calloc(1, size)
                    } else {
                        libc::malloc(size)
                    }
                }
            }
            heap_alloc as usize
        }
        "HeapFree" => {
            extern "win64" fn heap_free(_heap: *mut c_void, _flags: u32, mem: *mut c_void) -> i32 {
                unsafe { libc::free(mem) };
                1
            }
            heap_free as usize
        }
        "HeapReAlloc" => {
            extern "win64" fn heap_realloc(
                _heap: *mut c_void,
                flags: u32,
                mem: *mut c_void,
                size: usize,
            ) -> *mut c_void {
                if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
                    return null_mut();
                }
                unsafe {
                    let old = libc::malloc_usable_size(mem);
                    let new = libc::realloc(mem, size);
                    if !new.is_null() && flags & HEAP_ZERO_MEMORY != 0 && size > old {
                        libc::memset(new.cast::<u8>().add(old).cast(), 0, size - old);
                    }
                    new
                }
            }
            heap_realloc as usize
        }
        "HeapSize" => {
            extern "win64" fn heap_size(_heap: *mut c_void, _flags: u32, mem: *const c_void) -> usize {
                if mem.is_null() {
                    return usize::MAX;
                }
                unsafe { libc::malloc_usable_size(mem.cast_mut()) }
            }
            heap_size as usize
        }
        "HeapValidate" => {
            extern "win64" fn heap_validate(
                _heap: *mut c_void,
                _flags: u32,
                _mem: *const c_void,
            ) -> i32 {
                1
            }
            heap_validate as usize
        }
        "HeapWalk" => {
            extern "win64" fn heap_walk(_heap: *mut c_void, _entry: *mut c_void) -> i32 {
                get_tib().set_last_error(ERROR_NO_MORE_ITEMS);
                0
            }
            heap_walk as usize
        }
        "HeapQueryInformation" => {
            extern "win64" fn heap_query_information(
                _heap: *mut c_void,
                _class: i32,
                info: *mut c_void,
                len: usize,
                ret_len: *mut usize,
            ) -> i32 {
                if !info.is_null() && len >= 4 {
                    unsafe { info.cast::<u32>().write(0) };
                }
                if !ret_len.is_null() {
                    unsafe { ret_len.write(4) };
                }
                1
            }
            heap_query_information as usize
        }
        "HeapCompact" => {
            extern "win64" fn heap_compact(_heap: *mut c_void, _flags: u32) -> usize {
                get_tib().set_last_error(0);
                0
            }
            heap_compact as usize
        }
        "LocalFree" => {
            extern "win64" fn local_free(mem: *mut c_void) -> *mut c_void {
                unsafe { libc::free(mem) };
                null_mut()
            }
            local_free as usize
        }
        "InitializeCriticalSectionAndSpinCount" => {
            extern "win64" fn icsasc(cs: *mut (), _sc: u32) -> bool {
                warn!("todo: threads");
                // *cs = unsafe {Mutex::new(());};
                true
            }
            icsasc as usize
        }
        "DeleteCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "EnterCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "LeaveCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "TlsAlloc" => {
            extern "win64" fn alloc() -> u32 {
                let index = get_tib().get_peb().lock().tls_alloc();
                match index {
                    Some(index) => {
                        debug!("tls alloc: {index}");
                        index
                    }
                    None => {
                        warn!("tls out of indexes");
                        TLS_OUT_OF_INDEXES
                    }
                }
            }
            alloc as usize
        }
        "TlsFree" => {
            extern "win64" fn free(index: u32) -> i32 {
                let tib = get_tib();
                if !tib.get_peb().lock().tls_free(index) {
                    warn!("tls free of unallocated index: {index}");
                    return 0;
                }
                tib.tls_set(index, null_mut());
                1
            }
            free as usize
        }
        "TlsGetValue" => {
            extern "win64" fn get(index: u32) -> *mut c_void {
                let tib = get_tib();
                match tib.tls_get(index) {
                    Some(value) => {
                        tib.set_last_error(0);
                        value
                    }
                    None => {
                        warn!("tls get of out of range index: {index}");
                        tib.set_last_error(ERROR_INVALID_PARAMETER);
                        null_mut()
                    }
                }
            }
            get as usize
        }
        "TlsSetValue" => {
            extern "win64" fn set(index: u32, value: *mut c_void) -> i32 {
                let tib = get_tib();
                if !tib.tls_set(index, value) {
                    warn!("tls set of out of range index: {index}");
                    tib.set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                1
            }
            set as usize
        }
        "LoadLibraryExW" => {
            extern "win64" fn load_lib(name: *const u16, file: *const (), flags: u32) -> *const () {
                warn!("dyn load");
                let name = unsafe { widestring::U16CStr::from_ptr_str(name) };
                warn!("dyn load w {name:?}");
                // get_tib().set_last_error(0x11223344);
                0x11223344 as *const ()
            }
            load_lib as usize
        }
        "GetProcAddress" => {
            extern "win64" fn load_lib(module: *const (), proc: *const c_char) -> *const () {
                let proc = unsafe { CStr::from_ptr(proc) };
                warn!("get proc: {proc:?}");
                // get_tib().set_last_error(0x11223344);
                null()
            }
            load_lib as usize
        }
        "SetLastError" => {
            extern "win64" fn set_last_error(e: u32) {
                get_tib().set_last_error(e);
            }
            set_last_error as usize
        }
        "GetLastError" => {
            extern "win64" fn get_last_error() -> u32 {
                let tib = get_tib();
                tib.last_error()
            }
            get_last_error as usize
        }
        "GetSystemTimeAsFileTime" => {
            extern "win64" fn time(_out: *mut ()) {
                info!("queried time")
            }
            time as usize
        }
        "GetCurrentThreadId" => {
            extern "win64" fn thread() -> u32 {
                info!("queried thread id");
                42
            }
            thread as usize
        }
        "GetCurrentProcessId" => {
            extern "win64" fn process() -> u32 {
                info!("queried process id");
                42
            }
            process as usize
        }
        "QueryPerformanceCounter" => {
            extern "win64" fn perfcnt(out: &mut u64) {
                info!("queried perf cnt");
                *out = 42;
            }
            perfcnt as usize
        }

        "EncodePointer" => {
            extern "win64" fn encode(i: usize) -> usize {
                !i
            }
            encode as usize
        }
        "setlocale" => {
            extern "win64" fn perfcnt(cat: i32, loc: *const c_char) -> *const c_char {
                let locale = if loc.is_null() {
                    None
                } else {
                    Some(unsafe { CStr::from_ptr(loc) })
                };
                info!("setlocale! {locale:?}");
                unsafe { libc::setlocale(cat, loc) }
            }
            perfcnt as usize
        }
        // "_lock_locales" |
        // | "_unlock_locales"
        // | "___lc_codepage_func"
        // | "___lc_locale_name_func"
        // | "__pctype_func"
        //| "_wcsdup"
        "_initialize_onexit_table" => {
            extern "win64" fn dummy() {}
            dummy as usize
        }
        _ => return None,
    })
}
