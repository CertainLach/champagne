use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::iter::once;
use std::mem::offset_of;
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::wininternals::{get_tib, PebLike, TLS_OUT_OF_INDEXES};

const SECONDS_1601_TO_1970: u64 = 11644473600;

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

pub struct WinFn {
    pub name: &'static str,
    pub ptr: fn() -> usize,
}
inventory::collect!(WinFn);

macro_rules! winfn {
    ($(
        $(#[alias($($alias:literal),* $(,)?)])?
        fn $name:ident($($p:ident: $t:ty),* $(,)?) $(-> $r:ty)? $body:block
    )*) => {$(
        #[allow(non_snake_case)]
        extern "win64" fn $name($($p: $t),*) $(-> $r)? $body
        inventory::submit! {
            WinFn { name: stringify!($name), ptr: || $name as *const () as usize }
        }
        $($(
            inventory::submit! {
                WinFn { name: $alias, ptr: || $name as *const () as usize }
            }
        )*)?
    )*};
}

pub fn override_import(_module: &str, name: &str) -> Option<usize> {
    static TABLE: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            inventory::iter::<WinFn>
                .into_iter()
                .map(|f| (f.name, (f.ptr)()))
                .collect()
        })
        .get(name)
        .copied()
}

winfn! {
    fn malloc(size: usize) -> *mut c_void {
        dbg!(size);
        unsafe { libc::malloc(size) }
    }
    // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)

    fn calloc(nobj: usize, size: usize) -> *mut c_void {
        dbg!(nobj, size);
        unsafe { libc::calloc(nobj, size) }
    }

    fn free(size: *mut c_void) {
        dbg!(size);
        unsafe { libc::free(size) }
    }

    fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
        dbg!(dst, c, n);
        unsafe { libc::memset(dst, c, n) }
    }
    // fuckup_cc("memset", libc::memset as unsafe extern "C" fn(_, _, _) -> _)

    fn memcpy(dst: *mut c_void, c: *const c_void, n: usize) -> *mut c_void {
        unsafe { libc::memcpy(dst, c, n) }
    }
    // fuckup_cc("memcpy", libc::memcpy as unsafe extern "C" fn(_, _, _) -> _)

    fn setlocale(cat: i32, loc: *const c_char) -> *const c_char {
        let locale = if loc.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(loc) })
        };
        info!("setlocale! {locale:?}");
        unsafe { libc::setlocale(cat, loc) }
    }
    // "getenv" => fuckup_cc("getenv", libc::getenv as unsafe extern "C" fn(_) -> _),

    fn EncodePointer(i: usize) -> usize {
        !i
    }
}

winfn! {
    fn GetProcessHeap() -> *mut c_void {
        process_heap()
    }

    fn HeapAlloc(_heap: *mut c_void, flags: u32, size: usize) -> *mut c_void {
        unsafe {
            if flags & HEAP_ZERO_MEMORY != 0 {
                libc::calloc(1, size)
            } else {
                libc::malloc(size)
            }
        }
    }

    fn HeapFree(_heap: *mut c_void, _flags: u32, mem: *mut c_void) -> i32 {
        unsafe { libc::free(mem) };
        1
    }

    fn HeapReAlloc(_heap: *mut c_void, flags: u32, mem: *mut c_void, size: usize) -> *mut c_void {
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

    fn HeapSize(_heap: *mut c_void, _flags: u32, mem: *const c_void) -> usize {
        if mem.is_null() {
            return usize::MAX;
        }
        unsafe { libc::malloc_usable_size(mem.cast_mut()) }
    }

    fn HeapValidate(_heap: *mut c_void, _flags: u32, _mem: *const c_void) -> i32 {
        1
    }

    fn HeapWalk(_heap: *mut c_void, _entry: *mut c_void) -> i32 {
        get_tib().set_last_error(ERROR_NO_MORE_ITEMS);
        0
    }

    fn HeapQueryInformation(
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

    fn HeapCompact(_heap: *mut c_void, _flags: u32) -> usize {
        get_tib().set_last_error(0);
        0
    }

    fn LocalFree(mem: *mut c_void) -> *mut c_void {
        unsafe { libc::free(mem) };
        null_mut()
    }
}

winfn! {
    fn GetStartupInfoW(info: *mut StartupInfoW) {
        if info.is_null() {
            return;
        }
        unsafe {
            info.write_bytes(0, 1);
            (*info).cb = size_of::<StartupInfoW>() as u32;
        }
    }

    fn GetStdHandle(which: u32) -> *mut c_void {
        match which {
            STD_INPUT_HANDLE => 1usize as *mut c_void,
            STD_OUTPUT_HANDLE => 2usize as *mut c_void,
            STD_ERROR_HANDLE => 3usize as *mut c_void,
            _ => INVALID_HANDLE_VALUE as *mut c_void,
        }
    }

    fn SetStdHandle(_which: u32, _handle: *mut c_void) -> i32 {
        1
    }

    fn GetFileType(handle: *mut c_void) -> u32 {
        match std_handle_fd(handle) {
            Some(_) => FILE_TYPE_CHAR,
            None => FILE_TYPE_UNKNOWN,
        }
    }

    fn GetCommandLineW() -> *mut u16 {
        static CMD: OnceLock<Vec<u16>> = OnceLock::new();
        wide(&CMD, "dllloader")
    }

    fn GetCommandLineA() -> *const c_char {
        c"dllloader".as_ptr()
    }

    fn GetEnvironmentStringsW() -> *mut u16 {
        static ENV: OnceLock<Vec<u16>> = OnceLock::new();
        ENV.get_or_init(|| vec![0, 0]).as_ptr().cast_mut()
    }

    fn FreeEnvironmentStringsW(_env: *mut u16) -> i32 {
        1
    }

    fn GetModuleFileNameW(_module: *mut c_void, buf: *mut u16, size: u32) -> u32 {
        static NAME: OnceLock<Vec<u16>> = OnceLock::new();
        let name =
            NAME.get_or_init(|| r"C:\dllloader.exe".encode_utf16().chain(once(0)).collect());
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

    fn GetModuleHandleW(name: *const u16) -> *mut c_void {
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

    fn GetModuleHandleExW(_flags: u32, name: *const u16, out: *mut *mut c_void) -> i32 {
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

    fn GetCurrentProcess() -> *mut c_void {
        INVALID_HANDLE_VALUE as *mut c_void
    }

    fn GetCurrentThread() -> *mut c_void {
        (INVALID_HANDLE_VALUE - 1) as *mut c_void
    }

    fn GetCurrentThreadId() -> u32 {
        info!("queried thread id");
        42
    }

    fn GetCurrentProcessId() -> u32 {
        info!("queried process id");
        42
    }

    fn GetSystemInfo(info: *mut SystemInfo) {
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

    fn IsProcessorFeaturePresent(feature: u32) -> i32 {
        debug!("queried processor feature {feature}");
        0
    }

    fn IsDebuggerPresent() -> i32 {
        0
    }

    fn ExitProcess(code: u32) {
        info!("image requested exit: {code}");
        std::process::exit(code as i32)
    }

    fn TerminateProcess(_process: *mut c_void, code: u32) -> i32 {
        info!("image requested termination: {code}");
        std::process::exit(code as i32)
    }
}

winfn! {
    fn SetLastError(e: u32) {
        get_tib().set_last_error(e);
    }

    fn GetLastError() -> u32 {
        get_tib().last_error()
    }

    fn SetErrorMode(_mode: u32) -> u32 {
        0
    }

    fn SetUnhandledExceptionFilter(_filter: *mut c_void) -> *mut c_void {
        null_mut()
    }

    fn UnhandledExceptionFilter(_info: *mut c_void) -> i32 {
        warn!("unhandled exception");
        1
    }

    fn RaiseException(code: u32, flags: u32, _n_args: u32, _args: *const usize) {
        panic!("todo: seh: exception {code:#x} raised with flags {flags:#x}");
    }

    fn OutputDebugStringW(s: *const u16) {
        if s.is_null() {
            return;
        }
        let s = unsafe { widestring::U16CStr::from_ptr_str(s) };
        info!("image debug output: {}", s.to_string_lossy());
    }
}

winfn! {
    #[alias("GetOEMCP")]
    fn GetACP() -> u32 {
        CP_UTF8
    }

    fn GetCPInfo(_cp: u32, info: *mut CpInfo) -> i32 {
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

    fn IsValidCodePage(cp: u32) -> i32 {
        i32::from(cp == CP_UTF8)
    }

    fn MultiByteToWideChar(
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

    fn WideCharToMultiByte(
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

    fn GetStringTypeW(_info_type: u32, src: *const u16, src_len: i32, out: *mut u16) -> i32 {
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

    fn LCMapStringW(
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

    fn CompareStringW(
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

    fn GetUserDefaultLCID() -> u32 {
        LCID_EN_US
    }

    fn IsValidLocale(locale: u32, _flags: u32) -> i32 {
        i32::from(locale == LCID_EN_US || locale == LOCALE_USER_DEFAULT)
    }
}

winfn! {
    fn TlsAlloc() -> u32 {
        match get_tib().get_peb().lock().tls_alloc() {
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

    fn TlsFree(index: u32) -> i32 {
        let tib = get_tib();
        if !tib.get_peb().lock().tls_free(index) {
            warn!("tls free of unallocated index: {index}");
            return 0;
        }
        tib.tls_set(index, null_mut());
        1
    }

    fn TlsGetValue(index: u32) -> *mut c_void {
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

    fn TlsSetValue(index: u32, value: *mut c_void) -> i32 {
        let tib = get_tib();
        if !tib.tls_set(index, value) {
            warn!("tls set of out of range index: {index}");
            tib.set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        1
    }
}

winfn! {
    fn InitializeCriticalSectionAndSpinCount(cs: *mut (), _sc: u32) -> i32 {
        warn!("todo: threads");
        // *cs = unsafe {Mutex::new(());};
        let _ = cs;
        1
    }

    fn DeleteCriticalSection(_cs: *mut ()) {
        warn!("todo: threads");
    }

    fn EnterCriticalSection(_cs: *mut ()) {
        warn!("todo: threads");
    }

    fn LeaveCriticalSection(_cs: *mut ()) {
        warn!("todo: threads");
    }

    fn InitializeSListHead(head: *mut *mut c_void) {
        if !head.is_null() {
            unsafe { head.write_bytes(0, 2) };
        }
    }

    fn QueryDepthSList(head: *mut *mut c_void) -> u16 {
        let mut n = 0u16;
        let mut cur = unsafe { head.read() };
        while !cur.is_null() {
            n = n.saturating_add(1);
            cur = unsafe { cur.cast::<*mut c_void>().read() };
        }
        n
    }

    fn InterlockedPopEntrySList(head: *mut *mut c_void) -> *mut c_void {
        unsafe {
            let first = head.read();
            if first.is_null() {
                return null_mut();
            }
            head.write(first.cast::<*mut c_void>().read());
            first
        }
    }

    fn InterlockedPushEntrySList(head: *mut *mut c_void, entry: *mut *mut c_void) -> *mut c_void {
        unsafe {
            let prev = head.read();
            entry.write(prev);
            head.write(entry.cast());
            prev
        }
    }

    fn InterlockedFlushSList(head: *mut *mut c_void) -> *mut c_void {
        unsafe {
            let prev = head.read();
            head.write(null_mut());
            prev
        }
    }
}

winfn! {
    fn GetSystemTimeAsFileTime(out: *mut u64) {
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

    fn QueryPerformanceCounter(out: *mut u64) -> i32 {
        if out.is_null() {
            return 0;
        }
        static START: OnceLock<Instant> = OnceLock::new();
        let elapsed = START.get_or_init(Instant::now).elapsed();
        unsafe { out.write_unaligned(elapsed.as_nanos() as u64 / 100) };
        1
    }

    fn QueryPerformanceFrequency(out: *mut u64) -> i32 {
        if out.is_null() {
            return 0;
        }
        unsafe { out.write_unaligned(10_000_000) };
        1
    }

    fn Sleep(ms: u32) {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}

winfn! {
    fn LoadLibraryExW(name: *const u16, file: *const (), flags: u32) -> *const () {
        let _ = (file, flags);
        warn!("dyn load");
        let name = unsafe { widestring::U16CStr::from_ptr_str(name) };
        warn!("dyn load w {name:?}");
        // get_tib().set_last_error(0x11223344);
        0x11223344 as *const ()
    }

    fn GetProcAddress(module: *const (), proc: *const c_char) -> *const () {
        let _ = module;
        let proc = unsafe { CStr::from_ptr(proc) };
        warn!("get proc: {proc:?}");
        // get_tib().set_last_error(0x11223344);
        null()
    }
}

// "_lock_locales" |
// | "_unlock_locales"
// | "___lc_codepage_func"
// | "___lc_locale_name_func"
// | "__pctype_func"
//| "_wcsdup"
