use std::ffi::c_void;
use std::ptr::null_mut;

use champagne_kernel::peb::{PebLike as _, get_peb};
use champagne_kernel::tib::{TLS_OUT_OF_INDEXES, get_tib};
use champagne_macros::winfn;
use tracing::{debug, warn};

use crate::peb::ERROR_INVALID_PARAMETER;

#[winfn]
fn TlsAlloc() -> u32 {
	match get_peb().lock().tls_alloc() {
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

#[winfn]
fn TlsFree(index: u32) -> i32 {
	let tib = get_tib();
	if !tib.get_peb().lock().tls_free(index) {
		warn!("tls free of unallocated index: {index}");
		return 0;
	}
	tib.tls_set(index, null_mut());
	1
}

#[winfn]
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

#[winfn]
fn TlsSetValue(index: u32, value: *mut c_void) -> i32 {
	let tib = get_tib();
	if !tib.tls_set(index, value) {
		warn!("tls set of out of range index: {index}");
		tib.set_last_error(ERROR_INVALID_PARAMETER);
		return 0;
	}
	1
}
