use std::cmp::Ordering;
use std::ffi::{c_char, c_void, CStr};
use std::iter::once;
use std::slice;
use std::mem::offset_of;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const SECONDS_1601_TO_1970: u64 = 11644473600;

use crate::wininternals::{get_tib, PebLike, TLS_OUT_OF_INDEXES};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const HEAP_ZERO_MEMORY: u32 = 0x8;
const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;

const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
const INVALID_HANDLE_VALUE: usize = usize::MAX;
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_CHAR: u32 = 2;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const CP_UTF8: u32 = 65001;
const LCID_EN_US: u32 = 0x0409;
const LOCALE_USER_DEFAULT: u32 = 0x0400;
const NORM_IGNORECASE: u32 = 0x1;
const LCMAP_LOWERCASE: u32 = 0x100;
const LCMAP_UPPERCASE: u32 = 0x200;
const CSTR_LESS_THAN: i32 = 1;
const CSTR_EQUAL: i32 = 2;
const CSTR_GREATER_THAN: i32 = 3;
const C1_UPPER: u16 = 0x1;
const C1_LOWER: u16 = 0x2;
const C1_DIGIT: u16 = 0x4;
const C1_SPACE: u16 = 0x8;
const C1_PUNCT: u16 = 0x10;
const C1_CNTRL: u16 = 0x20;
const C1_BLANK: u16 = 0x40;
const C1_XDIGIT: u16 = 0x80;
const C1_ALPHA: u16 = 0x100;
const C1_DEFINED: u16 = 0x200;

static PROCESS_HEAP: u8 = 0;

fn process_heap() -> *mut c_void {
    (&raw const PROCESS_HEAP).cast_mut().cast()
}

fn wide(cell: &'static OnceLock<Vec<u16>>, s: &str) -> *mut u16 {
    cell.get_or_init(|| s.encode_utf16().chain(once(0)).collect())
        .as_ptr()
        .cast_mut()
}

fn std_handle_fd(handle: *mut c_void) -> Option<i32> {
    match handle as usize {
        1 => Some(0),
        2 => Some(1),
        3 => Some(2),
        _ => None,
    }
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}
const _: () = assert!(size_of::<StartupInfoW>() == 104);
const _: () = assert!(offset_of!(StartupInfoW, h_std_input) == 80);

#[repr(C)]
struct CpInfo {
    max_char_size: u32,
    default_char: [u8; 2],
    lead_byte: [u8; 12],
}

fn mb_input<'a>(src: *const u8, len: i32) -> &'a [u8] {
    unsafe {
        if len < 0 {
            CStr::from_ptr(src.cast()).to_bytes_with_nul()
        } else {
            slice::from_raw_parts(src, len as usize)
        }
    }
}

fn wc_input<'a>(src: *const u16, len: i32) -> &'a [u16] {
    unsafe {
        if len < 0 {
            widestring::U16CStr::from_ptr_str(src).as_slice_with_nul()
        } else {
            slice::from_raw_parts(src, len as usize)
        }
    }
}

fn emit<T: Copy>(out: &[T], dst: *mut T, dst_len: i32) -> i32 {
    if dst_len == 0 {
        return out.len() as i32;
    }
    if dst.is_null() || out.len() > dst_len as usize {
        get_tib().set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { dst.copy_from_nonoverlapping(out.as_ptr(), out.len()) };
    out.len() as i32
}

#[repr(C)]
struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: *mut c_void,
    maximum_application_address: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}
const _: () = assert!(size_of::<SystemInfo>() == 48);

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
        "GetStartupInfoW" => {
            extern "win64" fn get_startup_info(info: *mut StartupInfoW) {
                if info.is_null() {
                    return;
                }
                unsafe {
                    info.write_bytes(0, 1);
                    (*info).cb = size_of::<StartupInfoW>() as u32;
                }
            }
            get_startup_info as usize
        }
        "GetStdHandle" => {
            extern "win64" fn get_std_handle(which: u32) -> *mut c_void {
                match which {
                    STD_INPUT_HANDLE => 1usize as *mut c_void,
                    STD_OUTPUT_HANDLE => 2usize as *mut c_void,
                    STD_ERROR_HANDLE => 3usize as *mut c_void,
                    _ => INVALID_HANDLE_VALUE as *mut c_void,
                }
            }
            get_std_handle as usize
        }
        "SetStdHandle" => {
            extern "win64" fn set_std_handle(_which: u32, _handle: *mut c_void) -> i32 {
                1
            }
            set_std_handle as usize
        }
        "GetFileType" => {
            extern "win64" fn get_file_type(handle: *mut c_void) -> u32 {
                match std_handle_fd(handle) {
                    Some(_) => FILE_TYPE_CHAR,
                    None => FILE_TYPE_UNKNOWN,
                }
            }
            get_file_type as usize
        }
        "GetCommandLineW" => {
            extern "win64" fn get_command_line() -> *mut u16 {
                static CMD: OnceLock<Vec<u16>> = OnceLock::new();
                wide(&CMD, "dllloader")
            }
            get_command_line as usize
        }
        "GetCommandLineA" => {
            extern "win64" fn get_command_line() -> *const c_char {
                c"dllloader".as_ptr()
            }
            get_command_line as usize
        }
        "GetEnvironmentStringsW" => {
            extern "win64" fn get_environment_strings() -> *mut u16 {
                static ENV: OnceLock<Vec<u16>> = OnceLock::new();
                ENV.get_or_init(|| vec![0, 0]).as_ptr().cast_mut()
            }
            get_environment_strings as usize
        }
        "FreeEnvironmentStringsW" => {
            extern "win64" fn free_environment_strings(_env: *mut u16) -> i32 {
                1
            }
            free_environment_strings as usize
        }
        "GetModuleFileNameW" => {
            extern "win64" fn get_module_file_name(
                _module: *mut c_void,
                buf: *mut u16,
                size: u32,
            ) -> u32 {
                static NAME: OnceLock<Vec<u16>> = OnceLock::new();
                let name = NAME.get_or_init(|| {
                    r"C:\dllloader.exe".encode_utf16().chain(once(0)).collect()
                });
                if buf.is_null() || size == 0 {
                    return 0;
                }
                let copy = name.len().min(size as usize);
                unsafe { buf.copy_from_nonoverlapping(name.as_ptr(), copy) };
                if copy == size as usize {
                    unsafe { buf.add(copy - 1).write(0) };
                    get_tib().set_last_error(ERROR_INSUFFICIENT_BUFFER);
                    return size;
                }
                copy as u32 - 1
            }
            get_module_file_name as usize
        }
        "GetModuleHandleW" => {
            extern "win64" fn get_module_handle(name: *const u16) -> *mut c_void {
                if name.is_null() {
                    return process_heap();
                }
                let name = unsafe { widestring::U16CStr::from_ptr_str(name) }.to_string_lossy();
                match get_tib().get_peb().find_entry(&name.to_lowercase()) {
                    Some(entry) => entry.base().cast_mut().cast(),
                    None => {
                        warn!("module not found: {name}");
                        get_tib().set_last_error(ERROR_MOD_NOT_FOUND);
                        null_mut()
                    }
                }
            }
            get_module_handle as usize
        }
        "GetModuleHandleExW" => {
            extern "win64" fn get_module_handle_ex(
                _flags: u32,
                name: *const u16,
                out: *mut *mut c_void,
            ) -> i32 {
                if out.is_null() {
                    return 0;
                }
                if name.is_null() {
                    unsafe { out.write(process_heap()) };
                    return 1;
                }
                let name = unsafe { widestring::U16CStr::from_ptr_str(name) }.to_string_lossy();
                match get_tib().get_peb().find_entry(&name.to_lowercase()) {
                    Some(entry) => {
                        unsafe { out.write(entry.base().cast_mut().cast()) };
                        1
                    }
                    None => {
                        warn!("module not found: {name}");
                        unsafe { out.write(null_mut()) };
                        get_tib().set_last_error(ERROR_MOD_NOT_FOUND);
                        0
                    }
                }
            }
            get_module_handle_ex as usize
        }
        "GetCurrentProcess" => {
            extern "win64" fn get_current_process() -> *mut c_void {
                INVALID_HANDLE_VALUE as *mut c_void
            }
            get_current_process as usize
        }
        "GetCurrentThread" => {
            extern "win64" fn get_current_thread() -> *mut c_void {
                (INVALID_HANDLE_VALUE - 1) as *mut c_void
            }
            get_current_thread as usize
        }
        "GetSystemInfo" => {
            extern "win64" fn get_system_info(info: *mut SystemInfo) {
                if info.is_null() {
                    return;
                }
                unsafe {
                    info.write_bytes(0, 1);
                    (*info).processor_architecture = PROCESSOR_ARCHITECTURE_AMD64;
                    (*info).page_size = 4096;
                    (*info).allocation_granularity = 65536;
                    (*info).number_of_processors = 1;
                    (*info).active_processor_mask = 1;
                    (*info).minimum_application_address = 0x10000 as *mut c_void;
                    (*info).maximum_application_address = 0x7FFFFFFEFFFF as *mut c_void;
                }
            }
            get_system_info as usize
        }
        "IsProcessorFeaturePresent" => {
            extern "win64" fn is_processor_feature_present(feature: u32) -> i32 {
                debug!("queried processor feature {feature}");
                0
            }
            is_processor_feature_present as usize
        }
        "IsDebuggerPresent" => {
            extern "win64" fn is_debugger_present() -> i32 {
                0
            }
            is_debugger_present as usize
        }
        "SetUnhandledExceptionFilter" => {
            extern "win64" fn set_unhandled_exception_filter(_filter: *mut c_void) -> *mut c_void {
                null_mut()
            }
            set_unhandled_exception_filter as usize
        }
        "UnhandledExceptionFilter" => {
            extern "win64" fn unhandled_exception_filter(_info: *mut c_void) -> i32 {
                warn!("unhandled exception");
                1
            }
            unhandled_exception_filter as usize
        }
        "RaiseException" => {
            extern "win64" fn raise_exception(
                code: u32,
                flags: u32,
                _n_args: u32,
                _args: *const usize,
            ) {
                panic!("todo: seh: exception {code:#x} raised with flags {flags:#x}");
            }
            raise_exception as usize
        }
        "SetErrorMode" => {
            extern "win64" fn set_error_mode(_mode: u32) -> u32 {
                0
            }
            set_error_mode as usize
        }
        "ExitProcess" => {
            extern "win64" fn exit_process(code: u32) {
                info!("image requested exit: {code}");
                std::process::exit(code as i32)
            }
            exit_process as usize
        }
        "TerminateProcess" => {
            extern "win64" fn terminate_process(_process: *mut c_void, code: u32) -> i32 {
                info!("image requested termination: {code}");
                std::process::exit(code as i32)
            }
            terminate_process as usize
        }
        "GetACP" | "GetOEMCP" => {
            extern "win64" fn get_acp() -> u32 {
                CP_UTF8
            }
            get_acp as usize
        }
        "GetCPInfo" => {
            extern "win64" fn get_cp_info(_cp: u32, info: *mut CpInfo) -> i32 {
                if info.is_null() {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                unsafe {
                    info.write(CpInfo {
                        max_char_size: 4,
                        default_char: [b'?', 0],
                        lead_byte: [0; 12],
                    })
                };
                1
            }
            get_cp_info as usize
        }
        "IsValidCodePage" => {
            extern "win64" fn is_valid_code_page(cp: u32) -> i32 {
                i32::from(cp == CP_UTF8)
            }
            is_valid_code_page as usize
        }
        "MultiByteToWideChar" => {
            extern "win64" fn mb_to_wc(
                _cp: u32,
                _flags: u32,
                src: *const u8,
                src_len: i32,
                dst: *mut u16,
                dst_len: i32,
            ) -> i32 {
                if src.is_null() || src_len == 0 {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                let wide: Vec<u16> = String::from_utf8_lossy(mb_input(src, src_len))
                    .encode_utf16()
                    .collect();
                emit(&wide, dst, dst_len)
            }
            mb_to_wc as usize
        }
        "WideCharToMultiByte" => {
            extern "win64" fn wc_to_mb(
                _cp: u32,
                _flags: u32,
                src: *const u16,
                src_len: i32,
                dst: *mut u8,
                dst_len: i32,
                _default_char: *const c_char,
                used_default: *mut i32,
            ) -> i32 {
                if src.is_null() || src_len == 0 {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                if !used_default.is_null() {
                    unsafe { used_default.write(0) };
                }
                let narrow = String::from_utf16_lossy(wc_input(src, src_len));
                emit(narrow.as_bytes(), dst, dst_len)
            }
            wc_to_mb as usize
        }
        "GetStringTypeW" => {
            extern "win64" fn get_string_type(
                _info_type: u32,
                src: *const u16,
                src_len: i32,
                out: *mut u16,
            ) -> i32 {
                if src.is_null() || out.is_null() {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                let src = wc_input(src, src_len);
                for (i, unit) in src.iter().enumerate() {
                    let c = char::from_u32(*unit as u32).unwrap_or('\u{fffd}');
                    let mut ty = C1_DEFINED;
                    if c.is_uppercase() {
                        ty |= C1_UPPER | C1_ALPHA;
                    }
                    if c.is_lowercase() {
                        ty |= C1_LOWER | C1_ALPHA;
                    }
                    if c.is_alphabetic() {
                        ty |= C1_ALPHA;
                    }
                    if c.is_ascii_digit() {
                        ty |= C1_DIGIT;
                    }
                    if c.is_whitespace() {
                        ty |= C1_SPACE;
                    }
                    if c.is_ascii_punctuation() {
                        ty |= C1_PUNCT;
                    }
                    if c.is_control() {
                        ty |= C1_CNTRL;
                    }
                    if c == ' ' || c == '\t' {
                        ty |= C1_BLANK;
                    }
                    if c.is_ascii_hexdigit() {
                        ty |= C1_XDIGIT;
                    }
                    unsafe { out.add(i).write(ty) };
                }
                1
            }
            get_string_type as usize
        }
        "LCMapStringW" => {
            extern "win64" fn lc_map_string(
                _locale: u32,
                flags: u32,
                src: *const u16,
                src_len: i32,
                dst: *mut u16,
                dst_len: i32,
            ) -> i32 {
                if src.is_null() {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                let src = String::from_utf16_lossy(wc_input(src, src_len));
                let mapped: Vec<u16> = if flags & LCMAP_UPPERCASE != 0 {
                    src.to_uppercase().encode_utf16().collect()
                } else if flags & LCMAP_LOWERCASE != 0 {
                    src.to_lowercase().encode_utf16().collect()
                } else {
                    src.encode_utf16().collect()
                };
                emit(&mapped, dst, dst_len)
            }
            lc_map_string as usize
        }
        "CompareStringW" => {
            extern "win64" fn compare_string(
                _locale: u32,
                flags: u32,
                s1: *const u16,
                len1: i32,
                s2: *const u16,
                len2: i32,
            ) -> i32 {
                if s1.is_null() || s2.is_null() {
                    get_tib().set_last_error(ERROR_INVALID_PARAMETER);
                    return 0;
                }
                let a = String::from_utf16_lossy(wc_input(s1, len1));
                let b = String::from_utf16_lossy(wc_input(s2, len2));
                let ord = if flags & NORM_IGNORECASE != 0 {
                    a.to_lowercase().cmp(&b.to_lowercase())
                } else {
                    a.cmp(&b)
                };
                match ord {
                    Ordering::Less => CSTR_LESS_THAN,
                    Ordering::Equal => CSTR_EQUAL,
                    Ordering::Greater => CSTR_GREATER_THAN,
                }
            }
            compare_string as usize
        }
        "GetUserDefaultLCID" => {
            extern "win64" fn get_user_default_lcid() -> u32 {
                LCID_EN_US
            }
            get_user_default_lcid as usize
        }
        "IsValidLocale" => {
            extern "win64" fn is_valid_locale(locale: u32, _flags: u32) -> i32 {
                i32::from(locale == LCID_EN_US || locale == LOCALE_USER_DEFAULT)
            }
            is_valid_locale as usize
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
            extern "win64" fn time(out: *mut u64) {
                if out.is_null() {
                    return;
                }
                let unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let ticks = (unix.as_secs() + SECONDS_1601_TO_1970) * 10_000_000
                    + unix.subsec_nanos() as u64 / 100;
                unsafe { out.write_unaligned(ticks) };
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
            extern "win64" fn perfcnt(out: *mut u64) -> i32 {
                if out.is_null() {
                    return 0;
                }
                static START: OnceLock<Instant> = OnceLock::new();
                let elapsed = START.get_or_init(Instant::now).elapsed();
                unsafe { out.write_unaligned(elapsed.as_nanos() as u64 / 100) };
                1
            }
            perfcnt as usize
        }
        "QueryPerformanceFrequency" => {
            extern "win64" fn perffreq(out: *mut u64) -> i32 {
                if out.is_null() {
                    return 0;
                }
                unsafe { out.write_unaligned(10_000_000) };
                1
            }
            perffreq as usize
        }
        "Sleep" => {
            extern "win64" fn sleep(ms: u32) {
                std::thread::sleep(Duration::from_millis(ms as u64));
            }
            sleep as usize
        }
        "OutputDebugStringW" => {
            extern "win64" fn output_debug_string(s: *const u16) {
                if s.is_null() {
                    return;
                }
                let s = unsafe { widestring::U16CStr::from_ptr_str(s) };
                info!("image debug output: {}", s.to_string_lossy());
            }
            output_debug_string as usize
        }
        "InterlockedPushEntrySList" => {
            extern "win64" fn push(head: *mut *mut c_void, entry: *mut *mut c_void) -> *mut c_void {
                unsafe {
                    let prev = head.read();
                    entry.write(prev);
                    head.write(entry.cast());
                    prev
                }
            }
            push as usize
        }
        "InterlockedFlushSList" => {
            extern "win64" fn flush(head: *mut *mut c_void) -> *mut c_void {
                unsafe {
                    let prev = head.read();
                    head.write(null_mut());
                    prev
                }
            }
            flush as usize
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
