// TODO: cfg(not(windows))

use std::ffi::c_void;
use std::mem::swap;
use std::ptr::{null, null_mut};
use std::{ptr, slice};

use champagne_macros::winfn;
use digest::Digest;
use tracing::{debug, trace, warn};
use widestring::U16CStr;

use crate::certstore::{CertResult, VirtualCertStore};

const BCRYPT_ALG_MAGIC: u32 = 0xBC_A1_90_01;
const BCRYPT_HASH_MAGIC: u32 = 0xBC_0A_50_01;

const DUMMY_CRYPT_PROV: usize = 0x1001;
const DUMMY_HASH: usize = 0x1002;
const DUMMY_KEY: usize = 0x1003;
const DUMMY_MSG: usize = 0x1004;
const DUMMY_CERT_STORE: usize = 0x1005;
const DUMMY_CERT_MSG_STORE: usize = 0x1006;
const DUMMY_PUB_KEY: usize = 0x1007;
const DUMMY_CAT_ADMIN: usize = 0x1008;

#[derive(Clone, Copy, Debug)]
enum HashAlgorithm {
	Md5,
	Sha1,
	Sha256,
	Sha384,
	Sha512,
}

impl HashAlgorithm {
	fn digest_len(self) -> u32 {
		match self {
			Self::Md5 => 16,
			Self::Sha1 => 20,
			Self::Sha256 => 32,
			Self::Sha384 => 48,
			Self::Sha512 => 64,
		}
	}
}

struct AlgProvider {
	magic: u32,
	algorithm: HashAlgorithm,
}

enum HashState {
	Md5(md5::Md5),
	Sha1(sha1::Sha1),
	Sha256(sha2::Sha256),
	Sha384(sha2::Sha384),
	Sha512(sha2::Sha512),
}

struct HashContext {
	magic: u32,
	algorithm: HashAlgorithm,
	state: HashState,
}

impl HashContext {
	fn new(alg: HashAlgorithm) -> Self {
		let state = match alg {
			HashAlgorithm::Md5 => HashState::Md5(md5::Md5::new()),
			HashAlgorithm::Sha1 => HashState::Sha1(sha1::Sha1::new()),
			HashAlgorithm::Sha256 => HashState::Sha256(sha2::Sha256::new()),
			HashAlgorithm::Sha384 => HashState::Sha384(sha2::Sha384::new()),
			HashAlgorithm::Sha512 => HashState::Sha512(sha2::Sha512::new()),
		};
		Self {
			magic: BCRYPT_HASH_MAGIC,
			algorithm: alg,
			state,
		}
	}

	fn update(&mut self, data: &[u8]) {
		macro_rules! each { ($($v:ident),*) => { match &mut self.state { $(HashState::$v(h) => h.update(data),)* } } }
		each!(Md5, Sha1, Sha256, Sha384, Sha512);
	}

	fn finalize_into(self, output: &mut [u8]) {
		macro_rules! each { ($($v:ident),*) => { match self.state { $(HashState::$v(h) => { let r = h.finalize(); let n = output.len().min(r.len()); output[..n].copy_from_slice(&r[..n]); })* } } }
		each!(Md5, Sha1, Sha256, Sha384, Sha512);
	}
}

fn parse_algorithm(alg_id: *const u16) -> Option<HashAlgorithm> {
	if alg_id.is_null() {
		return None;
	}
	let name = unsafe { U16CStr::from_ptr_str(alg_id) }.to_string_lossy();
	match name.as_str() {
		"MD5" => Some(HashAlgorithm::Md5),
		"SHA1" => Some(HashAlgorithm::Sha1),
		"SHA256" => Some(HashAlgorithm::Sha256),
		"SHA384" => Some(HashAlgorithm::Sha384),
		"SHA512" => Some(HashAlgorithm::Sha512),
		_ => {
			warn!("unknown algorithm {name}");
			None
		}
	}
}

#[winfn]
fn BCryptOpenAlgorithmProvider(
	handle: *mut *mut AlgProvider,
	alg_id: *const u16,
	_implementation: *const u16,
	_flags: u32,
) -> u32 {
	if handle.is_null() {
		return 0xC000000D;
	}
	match parse_algorithm(alg_id) {
		Some(alg) => {
			let provider = Box::new(AlgProvider {
				magic: BCRYPT_ALG_MAGIC,
				algorithm: alg,
			});
			unsafe { handle.write(Box::into_raw(provider)) };
			0
		}
		None => {
			unsafe { handle.write(null_mut()) };
			0
		}
	}
}

#[winfn]
fn BCryptCloseAlgorithmProvider(handle: *mut AlgProvider, _flags: u32) -> u32 {
	if !handle.is_null() && unsafe { (*handle).magic } == BCRYPT_ALG_MAGIC {
		drop(unsafe { Box::from_raw(handle) });
	}
	0
}

#[winfn]
fn BCryptGenRandom(_alg: *mut c_void, buf: *mut u8, len: u32, _flags: u32) -> u32 {
	if buf.is_null() || len == 0 {
		return 0;
	}
	let slice = unsafe { slice::from_raw_parts_mut(buf, len as usize) };
	rand::fill(slice);
	0
}

fn get_alg_from_handle(handle: *mut AlgProvider) -> Option<HashAlgorithm> {
	if handle.is_null() {
		return None;
	}
	let magic = unsafe { ptr::read_unaligned(&(*handle).magic) };
	if magic == BCRYPT_ALG_MAGIC {
		Some(unsafe { (*handle).algorithm })
	} else {
		None
	}
}

#[winfn]
fn BCryptGetProperty(
	handle: *mut AlgProvider,
	property: *const u16,
	output: *mut u8,
	output_len: u32,
	result_len: *mut u32,
	_flags: u32,
) -> u32 {
	let prop_name = if !property.is_null() {
		unsafe { U16CStr::from_ptr_str(property) }.to_string_lossy()
	} else {
		String::new()
	};
	let digest_len = get_alg_from_handle(handle)
		.map(|a| a.digest_len())
		.unwrap_or(32);
	if prop_name == "HashDigestLength" {
		if !output.is_null() && output_len >= 4 {
			unsafe { (output as *mut u32).write(digest_len) };
		}
		if !result_len.is_null() {
			unsafe { result_len.write(4) };
		}
		return 0;
	}
	if prop_name == "ObjectLength" {
		if !output.is_null() && output_len >= 4 {
			unsafe { (output as *mut u32).write(128) };
		}
		if !result_len.is_null() {
			unsafe { result_len.write(4) };
		}
		return 0;
	}
	if !result_len.is_null() {
		unsafe { result_len.write(0) };
	}
	0
}

#[winfn]
fn BCryptCreateHash(
	alg: *mut AlgProvider,
	hash: *mut *mut HashContext,
	_object: *mut u8,
	_object_len: u32,
	_secret: *const u8,
	_secret_len: u32,
	_flags: u32,
) -> u32 {
	if hash.is_null() {
		return 0xC000000D;
	}
	let algorithm = get_alg_from_handle(alg).unwrap_or(HashAlgorithm::Sha256);
	let ctx = Box::new(HashContext::new(algorithm));
	unsafe { hash.write(Box::into_raw(ctx)) };
	0
}

#[winfn]
fn BCryptHashData(hash: *mut HashContext, input: *const u8, input_len: u32, _flags: u32) -> u32 {
	if hash.is_null() || input.is_null() || input_len == 0 {
		return 0;
	}
	if unsafe { (*hash).magic } != BCRYPT_HASH_MAGIC {
		return 0;
	}
	let data = unsafe { slice::from_raw_parts(input, input_len as usize) };
	unsafe { (*hash).update(data) };
	0
}

#[winfn]
fn BCryptFinishHash(hash: *mut HashContext, output: *mut u8, output_len: u32, _flags: u32) -> u32 {
	if hash.is_null() || output.is_null() || output_len == 0 {
		return 0;
	}
	if unsafe { (*hash).magic } != BCRYPT_HASH_MAGIC {
		unsafe { ptr::write_bytes(output, 0, output_len as usize) };
		return 0;
	}
	let digest_len = unsafe { (*hash).algorithm }.digest_len() as usize;
	let out_len = output_len as usize;
	let clone = unsafe {
		let alg = (*hash).algorithm;
		let mut new_ctx = HashContext::new(alg);
		swap(&mut (*hash).state, &mut new_ctx.state);
		new_ctx
	};
	let mut buf = vec![0u8; digest_len];
	clone.finalize_into(&mut buf);
	let copy_len = out_len.min(digest_len);
	unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), output, copy_len) };
	if out_len > digest_len {
		unsafe { ptr::write_bytes(output.add(digest_len), 0, out_len - digest_len) };
	}
	0
}

#[winfn]
fn BCryptDestroyHash(hash: *mut HashContext) -> u32 {
	if !hash.is_null() && unsafe { (*hash).magic } == BCRYPT_HASH_MAGIC {
		drop(unsafe { Box::from_raw(hash) });
	}
	0
}

#[winfn]
fn CryptAcquireContextW(
	prov: *mut usize,
	_container: *const u16,
	_provider: *const u16,
	_type: u32,
	_flags: u32,
) -> i32 {
	if !prov.is_null() {
		unsafe { prov.write(DUMMY_CRYPT_PROV) };
	}
	1
}

#[winfn]
fn CryptReleaseContext(_prov: usize, _flags: u32) -> i32 {
	1
}

#[winfn]
fn CryptCreateHash(_prov: usize, _alg: u32, _key: usize, _flags: u32, hash: *mut usize) -> i32 {
	if !hash.is_null() {
		unsafe { hash.write(DUMMY_HASH) };
	}
	1
}

#[winfn]
fn CryptDestroyHash(_hash: usize) -> i32 {
	1
}

#[winfn]
fn CryptHashData(_hash: usize, _data: *const u8, _len: u32, _flags: u32) -> i32 {
	1
}

#[winfn]
fn CryptGetHashParam(
	_hash: usize,
	_param: u32,
	data: *mut u8,
	data_len: *mut u32,
	_flags: u32,
) -> i32 {
	if !data_len.is_null() {
		let len = unsafe { *data_len };
		if !data.is_null() && len > 0 {
			unsafe { ptr::write_bytes(data, 0, len as usize) };
		}
	}
	1
}

#[winfn]
fn CryptVerifySignatureW(
	_hash: usize,
	_signature: *const u8,
	_sig_len: u32,
	_pub_key: usize,
	_description: *const u16,
	_flags: u32,
) -> i32 {
	1
}

#[winfn]
fn CryptImportPublicKeyInfoEx2(
	_encoding: u32,
	_info: *const c_void,
	_flags: u32,
	_aux: *const c_void,
	key: *mut *mut c_void,
) -> i32 {
	if !key.is_null() {
		unsafe { key.write(DUMMY_PUB_KEY as *mut _) };
	}
	1
}

#[winfn]
fn CryptDecodeObjectEx(
	_encoding: u32,
	_struct_type: *const c_void,
	_encoded: *const u8,
	_encoded_len: u32,
	flags: u32,
	_decode_para: *const c_void,
	output: *mut c_void,
	output_len: *mut u32,
) -> i32 {
	let needed = 256u32;
	if flags & 0x8000 != 0 {
		if !output.is_null() {
			let buf = unsafe { libc::calloc(1, needed as usize) };
			unsafe { (output as *mut *mut c_void).write(buf) };
		}
		if !output_len.is_null() {
			unsafe { output_len.write(needed) };
		}
	} else {
		if !output_len.is_null() {
			if output.is_null() {
				unsafe { output_len.write(needed) };
			} else {
				let avail = unsafe { *output_len };
				let copy = avail.min(needed) as usize;
				unsafe { ptr::write_bytes(output.cast::<u8>(), 0, copy) };
				unsafe { output_len.write(needed) };
			}
		}
	}
	1
}

#[winfn]
fn CryptDestroyKey(_key: usize) -> i32 {
	1
}

#[winfn]
fn CryptGenRandom(_prov: usize, len: u32, buf: *mut u8) -> i32 {
	if buf.is_null() || len == 0 {
		return 1;
	}
	let slice = unsafe { slice::from_raw_parts_mut(buf, len as usize) };
	rand::fill(slice);
	1
}

#[winfn]
fn CryptImportKey(
	_prov: usize,
	_data: *const u8,
	_data_len: u32,
	_pub_key: usize,
	_flags: u32,
	key: *mut usize,
) -> i32 {
	if !key.is_null() {
		unsafe { key.write(DUMMY_KEY) };
	}
	1
}

#[winfn]
fn CryptMsgOpenToDecode(
	_encoding: u32,
	_flags: u32,
	_msg_type: u32,
	_crypt_prov: usize,
	_recipient: *const c_void,
	_stream: *const c_void,
) -> *mut c_void {
	DUMMY_MSG as *mut c_void
}

#[winfn]
fn CryptMsgUpdate(_msg: *mut c_void, _data: *const u8, _len: u32, _final_call: i32) -> i32 {
	1
}

#[winfn]
fn CryptMsgGetParam(
	_msg: *mut c_void,
	param_type: u32,
	_index: u32,
	data: *mut c_void,
	data_len: *mut u32,
) -> i32 {
	if data_len.is_null() {
		return 0;
	}
	const CMSG_TYPE_PARAM: u32 = 1;
	const CMSG_SIGNED: u32 = 2;
	const CMSG_SIGNER_COUNT_PARAM: u32 = 5;
	const CMSG_CERT_COUNT_PARAM: u32 = 11;
	match param_type {
		CMSG_TYPE_PARAM => {
			if data.is_null() {
				unsafe { data_len.write(4) };
			} else {
				unsafe { (data as *mut u32).write(CMSG_SIGNED) };
				unsafe { data_len.write(4) };
			}
			1
		}
		CMSG_SIGNER_COUNT_PARAM | CMSG_CERT_COUNT_PARAM => {
			if data.is_null() {
				unsafe { data_len.write(4) };
			} else {
				unsafe { (data as *mut u32).write(1) };
				unsafe { data_len.write(4) };
			}
			1
		}
		_ => {
			if data.is_null() {
				unsafe { data_len.write(256) };
				return 1;
			}
			let avail = unsafe { *data_len };
			let size = avail.min(256) as usize;
			unsafe { ptr::write_bytes(data.cast::<u8>(), 0, size) };
			unsafe { data_len.write(size as u32) };
			1
		}
	}
}

#[winfn]
fn CryptMsgClose(_msg: *mut c_void) -> i32 {
	1
}

#[winfn]
fn CertOpenStore(
	_provider: *const c_void,
	_encoding: u32,
	_crypt_prov: usize,
	_flags: u32,
	_para: *const c_void,
) -> *mut c_void {
	DUMMY_CERT_STORE as *mut c_void
}

#[winfn]
fn CertCloseStore(_store: *mut c_void, _flags: u32) -> i32 {
	1
}

#[winfn]
fn CertCreateCertificateContext(
	_encoding: u32,
	_encoded: *const u8,
	_encoded_len: u32,
) -> *mut c_void {
	Box::into_raw(Box::new([0u8; 128])).cast()
}

#[winfn]
fn CertFreeCertificateContext(_ctx: *mut c_void) -> i32 {
	1
}

#[winfn]
fn CertGetCertificateChain(
	_engine: *mut c_void,
	_ctx: *mut c_void,
	_time: *const c_void,
	_store: *mut c_void,
	_para: *const c_void,
	_flags: u32,
	_reserved: *mut c_void,
	chain: *mut *mut c_void,
) -> i32 {
	debug!("CertGetCertificateChain called");
	if !chain.is_null() {
		unsafe { chain.write(null_mut()) };
	}
	0
}

#[winfn]
fn CertFreeCertificateChain(_chain: *mut c_void) {}

#[winfn]
fn CertVerifyCertificateChainPolicy(
	_policy: *const c_void,
	_chain: *mut c_void,
	_para: *const c_void,
	status: *mut c_void,
) -> i32 {
	if !status.is_null() {
		unsafe { ptr::write_bytes(status.cast::<u8>(), 0, 16) };
	}
	1
}

#[winfn]
fn CertGetCertificateContextProperty(
	_ctx: *mut c_void,
	_prop_id: u32,
	data: *mut c_void,
	data_len: *mut u32,
) -> i32 {
	if data_len.is_null() {
		return 0;
	}
	if data.is_null() {
		unsafe { data_len.write(64) };
		return 1;
	}
	let avail = unsafe { *data_len } as usize;
	let size = avail.min(64);
	unsafe { ptr::write_bytes(data.cast::<u8>(), 0, size) };
	unsafe { data_len.write(size as u32) };
	1
}

#[winfn]
fn CertGetNameStringW(
	_ctx: *mut c_void,
	_type: u32,
	_flags: u32,
	_type_para: *const c_void,
	name: *mut u16,
	size: u32,
) -> u32 {
	if !name.is_null() && size > 0 {
		unsafe { name.write(0) };
	}
	1
}

#[winfn]
fn CertNameToStrW(
	_encoding: u32,
	_name: *const c_void,
	_str_type: u32,
	str_buf: *mut u16,
	size: u32,
) -> u32 {
	if !str_buf.is_null() && size > 0 {
		unsafe { str_buf.write(0) };
	}
	1
}

#[winfn]
fn CertStrToNameW(
	_encoding: u32,
	_str: *const u16,
	_str_type: u32,
	_reserved: *mut c_void,
	encoded: *mut u8,
	encoded_len: *mut u32,
	_error: *mut *const u16,
) -> i32 {
	if !encoded_len.is_null() {
		if encoded.is_null() {
			unsafe { encoded_len.write(1) };
		} else {
			unsafe { encoded.write(0) };
			unsafe { encoded_len.write(1) };
		}
	}
	1
}

#[repr(C)]
struct CryptBlob {
	cb_data: u32,
	_pad: u32,
	pb_data: *const u8,
}
#[repr(C)]
struct CertContext {
	cert_encoding_type: u32,
	_pad0: u32,
	cert_encoded: *const u8,
	cert_encoded_len: u32,
	_pad1: u32,
	cert_info: *const CertInfo,
	cert_store: *mut c_void,
}
assert_size!(CertContext, 40);

#[repr(C)]
struct CertInfo {
	version: u32,
	_pad0: u32,
	serial_number: CryptBlob,
	signature_algorithm: [u8; 24],
	issuer: CryptBlob,
	_validity: [u8; 16],
	subject: CryptBlob,
}
assert_offset!(CertInfo, issuer, 48);
assert_offset!(CertInfo, subject, 80);
assert_size!(CertInfo, 96);

#[winfn]
fn CertFindCertificateInStore(
	_store: *mut c_void,
	_encoding: u32,
	_flags: u32,
	find_type: u32,
	find_para: *const CryptBlob,
	prev: *mut CertContext,
) -> *mut c_void {
	const CERT_FIND_SUBJECT_NAME: u32 = 0x20007;
	if find_type != CERT_FIND_SUBJECT_NAME || find_para.is_null() {
		return null_mut();
	}
	let blob = unsafe { &*find_para };
	if blob.pb_data.is_null() || blob.cb_data == 0 {
		return null_mut();
	}
	let subject_data = unsafe { slice::from_raw_parts(blob.pb_data, blob.cb_data as usize) };
	let query = &subject_data[..subject_data.len().min(16)];
	trace!(?query);
	let store = VirtualCertStore::current();
	let prev_der_len = if !prev.is_null() {
		unsafe { (*prev).cert_encoded_len as usize }
	} else {
		0
	};
	let cert = match store.and_then(|s| s.find_cert_by_subject_skip(subject_data, prev_der_len)) {
		Some(c) => {
			debug!("found cert, der_len={}", c.der.len());
			c
		}
		None => {
			debug!("synthesizing cert for subject len={}", blob.cb_data);
			CertResult {
				der: Vec::new(),
				subject: subject_data.to_vec(),
				issuer: subject_data.to_vec(),
			}
		}
	};
	let tail_size = cert.subject.len() + cert.issuer.len() + cert.der.len();
	let total = size_of::<CertContext>() + size_of::<CertInfo>() + tail_size;
	let mem = unsafe { libc::calloc(1, total) };
	if mem.is_null() {
		return null_mut();
	}
	let ctx = mem.cast::<CertContext>();
	let info = unsafe { ctx.add(1).cast::<CertInfo>() };
	let subj_buf = unsafe { info.add(1).cast::<u8>() };
	let issuer_buf = unsafe { subj_buf.add(cert.subject.len()) };
	let der_buf = unsafe { issuer_buf.add(cert.issuer.len()) };
	unsafe {
		ptr::copy_nonoverlapping(cert.subject.as_ptr(), subj_buf, cert.subject.len());
		ptr::copy_nonoverlapping(cert.issuer.as_ptr(), issuer_buf, cert.issuer.len());
		ptr::copy_nonoverlapping(cert.der.as_ptr(), der_buf, cert.der.len());
		ctx.write(CertContext {
			cert_encoding_type: 1,
			_pad0: 0,
			cert_encoded: der_buf,
			cert_encoded_len: cert.der.len() as u32,
			_pad1: 0,
			cert_info: info,
			cert_store: null_mut(),
		});
		info.write(CertInfo {
			version: 2,
			_pad0: 0,
			serial_number: CryptBlob {
				cb_data: 0,
				_pad: 0,
				pb_data: null(),
			},
			signature_algorithm: [0; 24],
			issuer: CryptBlob {
				cb_data: cert.subject.len() as u32,
				_pad: 0,
				pb_data: subj_buf,
			},
			_validity: [0; 16],
			subject: CryptBlob {
				cb_data: cert.subject.len() as u32,
				_pad: 0,
				pb_data: subj_buf,
			},
		});
	}
	ctx.cast()
}

#[winfn]
fn CertEnumCertificatesInStore(_store: *mut c_void, _prev: *mut c_void) -> *mut c_void {
	null_mut()
}

#[winfn]
fn CertDeleteCertificateFromStore(_ctx: *mut c_void) -> i32 {
	1
}

#[winfn]
fn CertAddEncodedCertificateToStore(
	_store: *mut c_void,
	_encoding: u32,
	encoded: *const u8,
	encoded_len: u32,
	_add_disposition: u32,
	_cert_ctx: *mut *mut c_void,
) -> i32 {
	1
}

#[winfn]
fn CryptDecodeObject(
	_encoding: u32,
	_struct_type: *const c_void,
	_encoded: *const u8,
	_encoded_len: u32,
	_flags: u32,
	output: *mut c_void,
	output_len: *mut u32,
) -> i32 {
	if output_len.is_null() {
		return 0;
	}
	if output.is_null() {
		unsafe { output_len.write(256) };
		return 1;
	}
	let avail = unsafe { *output_len } as usize;
	let size = avail.min(256);
	unsafe { ptr::write_bytes(output.cast::<u8>(), 0, size) };
	unsafe { output_len.write(size as u32) };
	1
}

#[winfn]
fn CryptImportPublicKeyInfo(
	_prov: usize,
	_encoding: u32,
	_info: *const c_void,
	key: *mut usize,
) -> i32 {
	if !key.is_null() {
		unsafe { key.write(DUMMY_KEY) };
	}
	1
}

#[winfn]
fn CryptQueryObject(
	_object_type: u32,
	_object: *const c_void,
	_expected_content: u32,
	_expected_format: u32,
	_flags: u32,
	_encoding: *mut u32,
	_content: *mut u32,
	_format: *mut u32,
	_cert_store: *mut *mut c_void,
	_msg: *mut *mut c_void,
	_context: *mut *mut c_void,
) -> i32 {
	0
}

#[winfn]
fn CryptStringToBinaryW(
	_str: *const u16,
	_str_len: u32,
	_flags: u32,
	_binary: *mut u8,
	binary_len: *mut u32,
	_skip: *mut u32,
	_flags_out: *mut u32,
) -> i32 {
	if !binary_len.is_null() {
		unsafe { binary_len.write(0) };
	}
	1
}

#[winfn]
fn WinVerifyTrust(_hwnd: *mut c_void, _action: *const c_void, _data: *mut c_void) -> i32 {
	0
}

#[winfn]
fn WTHelperProvDataFromStateData(_state: *mut c_void) -> *mut c_void {
	Box::into_raw(Box::new([0u8; 256])).cast()
}

#[winfn]
fn WTHelperGetProvSignerFromChain(
	_prov: *mut c_void,
	_idx: u32,
	_counter: i32,
	_signer_idx: u32,
) -> *mut c_void {
	Box::into_raw(Box::new([0u8; 256])).cast()
}

#[winfn]
fn WTHelperGetProvCertFromChain(_signer: *mut c_void, _idx: u32) -> *mut c_void {
	Box::into_raw(Box::new([0u8; 256])).cast()
}

#[winfn]
fn CryptCATOpen(
	_filename: *const u16,
	_open_flags: u32,
	_prov: usize,
	_pub_ver: u32,
	_transform: u32,
) -> *mut c_void {
	usize::MAX as *mut c_void
}

#[winfn]
fn CryptCATClose(_cat: *mut c_void) -> i32 {
	1
}

#[winfn]
fn CryptCATCatalogInfoFromContext(_cat: *mut c_void, _info: *mut c_void, _flags: u32) -> i32 {
	0
}

#[winfn]
fn CryptCATGetMemberInfo(_cat: *mut c_void, _tag: *const u16) -> *mut c_void {
	null_mut()
}

#[winfn]
fn CryptCATGetAttrInfo(_cat: *mut c_void, _member: *mut c_void, _tag: *const u16) -> *mut c_void {
	null_mut()
}

#[winfn]
fn CryptCATAdminEnumCatalogFromHash(
	_admin: *mut c_void,
	_hash: *const u8,
	_hash_len: u32,
	_flags: u32,
	_prev: *mut c_void,
) -> *mut c_void {
	null_mut()
}

#[winfn]
fn CryptCATAdminReleaseCatalogContext(_admin: *mut c_void, _cat: *mut c_void, _flags: u32) -> i32 {
	1
}

#[winfn(alias(CryptCATAdminAcquireContext2))]
fn CryptCATAdminAcquireContext(
	admin: *mut *mut c_void,
	_subsystem: *const c_void,
	_flags: u32,
) -> i32 {
	if !admin.is_null() {
		unsafe { admin.write(DUMMY_CAT_ADMIN as *mut c_void) };
	}
	1
}

#[winfn]
fn CryptCATAdminCalcHashFromFileHandle(
	_handle: *mut c_void,
	hash_len: *mut u32,
	hash: *mut u8,
	_flags: u32,
) -> i32 {
	if hash_len.is_null() {
		return 0;
	}
	let needed = 32u32;
	if hash.is_null() {
		unsafe { hash_len.write(needed) };
		return 1;
	}
	let avail = unsafe { *hash_len };
	let size = avail.min(needed) as usize;
	unsafe { ptr::write_bytes(hash, 0x42, size) };
	unsafe { hash_len.write(size as u32) };
	1
}

#[winfn]
fn CryptCATAdminReleaseContext(_admin: *mut c_void, _flags: u32) -> i32 {
	1
}

#[winfn]
fn NtGetCachedSigningLevel(
	_handle: *mut c_void,
	flags: *mut u32,
	signing_level: *mut u32,
	_thumbprint: *mut u8,
	_thumbprint_size: *mut u32,
	_thumbprint_algo: *mut u32,
) -> u32 {
	if !signing_level.is_null() {
		unsafe { signing_level.write(12) };
	}
	if !flags.is_null() {
		unsafe { flags.write(0) };
	}
	0
}

#[winfn]
fn NtSetCachedSigningLevel(
	_flags: u32,
	_level: u32,
	_source_files: *const *mut c_void,
	_source_count: u32,
	_target: *mut c_void,
) -> u32 {
	0
}

#[winfn]
fn WldpQueryWindowsLockdownMode(mode: *mut u32) -> u32 {
	if !mode.is_null() {
		unsafe { mode.write(0) }; // unlocked
	}
	0
}

#[winfn]
fn WofSetFileDataLocation(
	_handle: *mut c_void,
	_provider: u32,
	_info: *const c_void,
	_len: u32,
) -> u32 {
	0
}

#[winfn]
fn WofShouldCompressBinaries(_volume: *const u16, _algorithm: *mut u32) -> i32 {
	0
}

#[winfn]
fn CryptMsgControl(
	_msg: *mut c_void,
	_flags: u32,
	_ctrl_type: u32,
	_ctrl_para: *const c_void,
) -> i32 {
	1
}

#[winfn]
fn CryptGetMessageCertificates(
	_encoding: u32,
	_crypt_prov: usize,
	_flags: u32,
	_signed_blob: *const u8,
	_signed_blob_len: u32,
) -> *mut c_void {
	DUMMY_CERT_MSG_STORE as *mut c_void
}

#[winfn]
fn CertGetSubjectCertificateFromStore(
	_store: *mut c_void,
	_encoding: u32,
	_issuer_and_serial: *const c_void,
) -> *mut c_void {
	null_mut()
}
