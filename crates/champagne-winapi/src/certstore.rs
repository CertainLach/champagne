use std::cell::Cell;
use std::ptr::null;
use std::str;

use der_parser::der::parse_der;

thread_local! {
	static CURRENT: Cell<*const VirtualCertStore> = const { Cell::new(null()) };
}

#[derive(Default)]
pub struct VirtualCertStore {
	certs: Vec<StoredCert>,
}

struct StoredCert {
	der: Vec<u8>,
	subject: Vec<u8>,
	issuer: Vec<u8>,
}

pub struct CertResult {
	pub der: Vec<u8>,
	pub subject: Vec<u8>,
	pub issuer: Vec<u8>,
}

impl VirtualCertStore {
	pub fn new() -> Self {
		Self::default()
	}

	// To make it work both on windows and linux, it should instead hook certstore methods
	pub fn enter(&self) {
		CURRENT.with(|c| c.set(self as *const _));
	}

	pub fn current() -> Option<&'static VirtualCertStore> {
		CURRENT.with(|c| {
			let ptr = c.get();
			if ptr.is_null() {
				None
			} else {
				Some(unsafe { &*ptr })
			}
		})
	}

	pub fn extract_pkcs7_certs(&mut self, pkcs7_der: &[u8]) {
		let certs = match parse_pkcs7_certs(pkcs7_der) {
			Some(c) => c,
			None => {
				tracing::warn!("failed to extract certs from PKCS7");
				return;
			}
		};
		for cert_der in certs {
			if let Some((subject, issuer)) = extract_subject_issuer(&cert_der) {
				tracing::info!(
					"registered cert: subject_len={} issuer_len={} der_len={}",
					subject.len(),
					issuer.len(),
					cert_der.len()
				);
				self.certs.push(StoredCert {
					der: cert_der,
					subject,
					issuer,
				});
			}
		}
	}

	pub fn extract_all_certs_from_blob(&mut self, blob: &[u8]) {
		let mut i = 0;
		while i < blob.len().saturating_sub(4) {
			if blob[i] != 0x30 || blob[i + 1] != 0x82 {
				i += 1;
				continue;
			}
			let len = ((blob[i + 2] as usize) << 8) | blob[i + 3] as usize;
			let total = len + 4;
			if !(300..=3000).contains(&total) || i + total > blob.len() {
				i += 1;
				continue;
			}
			let candidate = &blob[i..i + total];
			if let Some((subject, issuer)) = extract_subject_issuer(candidate) {
				let cn = extract_cn(&subject);
				let already = self.certs.iter().any(|c| c.subject == subject);
				if !already {
					tracing::info!(
						"registered cert from blob: cn={:?} der_len={}",
						cn.and_then(|c| str::from_utf8(c).ok()),
						total
					);
					self.certs.push(StoredCert {
						der: candidate.to_vec(),
						subject,
						issuer,
					});
				}
			}
			i += total;
		}
	}

	pub fn extract_embedded_certs(&mut self, pe_data: &[u8]) {
		let needle = b"Microsoft Root Certificate Authority 2010";
		for i in 0..pe_data.len().saturating_sub(needle.len() + 300) {
			if pe_data[i] != 0x30 || pe_data[i + 1] != 0x82 {
				continue;
			}
			let len = ((pe_data[i + 2] as usize) << 8) | pe_data[i + 3] as usize;
			let total = len + 4;
			if !(800..=3000).contains(&total) || i + total > pe_data.len() {
				continue;
			}
			let blob = &pe_data[i..i + total];
			if blob.windows(needle.len()).any(|w| w == needle)
				&& let Some((subject, issuer)) = extract_subject_issuer(blob)
			{
				tracing::info!(
					"registered embedded root cert: {} bytes, subject_len={}, issuer_len={}",
					total,
					subject.len(),
					issuer.len()
				);
				self.certs.push(StoredCert {
					der: blob.to_vec(),
					subject,
					issuer,
				});
				return;
			}
		}
	}

	pub fn sort_self_signed_first(&mut self) {
		self.certs
			.sort_by_key(|c| if c.subject == c.issuer { 0 } else { 1 });
	}

	pub fn find_cert_by_subject_skip(
		&self,
		subject_der: &[u8],
		skip_der_len: usize,
	) -> Option<CertResult> {
		let query_cn = extract_cn(subject_der)?;
		let mut found_prev = skip_der_len == 0;
		for cert in &self.certs {
			if extract_cn(&cert.subject) != Some(query_cn) {
				continue;
			}
			if !found_prev {
				if cert.der.len() == skip_der_len {
					found_prev = true;
				}
				continue;
			}
			return Some(CertResult {
				der: cert.der.clone(),
				subject: cert.subject.clone(),
				issuer: cert.issuer.clone(),
			});
		}
		None
	}

	pub fn find_cert_by_subject(&self, subject_der: &[u8]) -> Option<CertResult> {
		let query_cn = extract_cn(subject_der)?;
		for cert in &self.certs {
			if extract_cn(&cert.subject) == Some(query_cn) {
				return Some(CertResult {
					der: cert.der.clone(),
					subject: cert.subject.clone(),
					issuer: cert.issuer.clone(),
				});
			}
		}
		None
	}
}

fn element_raw_bytes<'a>(input: &'a [u8], remaining: &'a [u8]) -> &'a [u8] {
	let consumed = input.len() - remaining.len();
	&input[..consumed]
}

fn skip_tlv(data: &[u8]) -> Option<&[u8]> {
	if data.is_empty() {
		return None;
	}
	let mut pos = 1;
	if data.len() < 2 {
		return None;
	}
	let len_byte = data[pos];
	pos += 1;
	let content_len = if len_byte < 0x80 {
		len_byte as usize
	} else {
		let num_bytes = (len_byte & 0x7F) as usize;
		if pos + num_bytes > data.len() {
			return None;
		}
		let mut l = 0usize;
		for i in 0..num_bytes {
			l = (l << 8) | data[pos + i] as usize;
		}
		pos += num_bytes;
		l
	};
	if pos + content_len > data.len() {
		return None;
	}
	Some(&data[pos + content_len..])
}

fn extract_subject_issuer(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
	if der.len() < 2 || der[0] != 0x30 {
		return None;
	}
	let cert_content = skip_tag_len(der)?;
	let mut pos = cert_content;
	if pos.is_empty() || pos[0] != 0x30 {
		return None;
	}
	let tbs_content = skip_tag_len(pos)?;
	pos = tbs_content;
	if !pos.is_empty() && (pos[0] & 0xC0) == 0x80 {
		pos = skip_tlv(pos)?;
	}
	pos = skip_tlv(pos)?;
	pos = skip_tlv(pos)?;
	let after_issuer = skip_tlv(pos)?;
	let issuer = &pos[..pos.len() - after_issuer.len()];
	pos = after_issuer;
	pos = skip_tlv(pos)?;
	let after_subject = skip_tlv(pos)?;
	let subject = &pos[..pos.len() - after_subject.len()];
	Some((subject.to_vec(), issuer.to_vec()))
}

fn skip_tag_len(data: &[u8]) -> Option<&[u8]> {
	if data.is_empty() {
		return None;
	}
	let mut pos = 1;
	if pos >= data.len() {
		return None;
	}
	let len_byte = data[pos];
	pos += 1;
	if len_byte < 0x80 {
		Some(&data[pos..])
	} else {
		let num = (len_byte & 0x7F) as usize;
		pos += num;
		if pos > data.len() {
			return None;
		}
		Some(&data[pos..])
	}
}

fn parse_pkcs7_certs(data: &[u8]) -> Option<Vec<Vec<u8>>> {
	let (_, outer) = parse_der(data).ok()?;
	let outer_seq = outer.as_sequence().ok()?;
	let content_explicit = outer_seq.get(1)?;
	let inner_bytes = content_explicit.content.as_slice().ok()?;
	let (_, content_inner) = parse_der(inner_bytes).ok()?;
	let signed_data = content_inner.as_sequence().ok()?;
	let mut certs = Vec::new();
	for el in signed_data.iter() {
		let tag = el.header.tag().0;
		let class = el.header.class();
		let constructed = el.header.is_constructed();
		if tag == 0 && constructed && class == der_parser::ber::Class::ContextSpecific {
			let cert_bytes = el.content.as_slice().ok()?;
			let mut pos = cert_bytes;
			while !pos.is_empty() {
				let (rem, _) = parse_der(pos).ok()?;
				let raw = element_raw_bytes(pos, rem);
				certs.push(raw.to_vec());
				pos = rem;
			}
			break;
		}
	}
	Some(certs)
}

fn extract_cn(name_der: &[u8]) -> Option<&[u8]> {
	let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
	let pos = name_der.windows(cn_oid.len()).position(|w| w == cn_oid)?;
	let after_oid = pos + cn_oid.len();
	if after_oid >= name_der.len() {
		return None;
	}
	if after_oid + 1 >= name_der.len() {
		return None;
	}
	let len = name_der[after_oid + 1] as usize;
	let start = after_oid + 2;
	if start + len > name_der.len() {
		return None;
	}
	Some(&name_der[start..start + len])
}
