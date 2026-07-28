use std::{io, result};

use champagne_kernel::ldr::LdrDataEntry;
use nix::errno::Errno;
use pelite::Export;
use pelite::pe64::{GetProcAddress as _, Pe as _, PeView};
use tracing::trace;

pub mod cc;
pub mod entry;
pub mod jitreg;
pub mod manual_map;
pub mod mkstub;

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("shm_open failed: {0}")]
	ShmOpen(Errno),
	#[error("mmap failed: {0}")]
	Mmap(io::Error),
	#[error("pe format error in {0}: {1}")]
	Pe(&'static str, pelite::Error),
	#[error("pe format error: {0}")]
	PeSanity(&'static str),
	#[error("region: {0}")]
	Region(#[from] region::Error),
}
impl Error {
	pub fn pe(err: &'static str) -> impl FnOnce(pelite::Error) -> Self {
		move |e| Self::Pe(err, e)
	}
	pub fn sanity(err: &'static str) -> Self {
		Self::PeSanity(err)
	}
}

pub type Result<T, E = Error> = result::Result<T, E>;

pub trait PeHandle {
	fn pe(&self) -> PeView<'_>;
}
impl PeHandle for LdrDataEntry {
	fn pe(&self) -> PeView<'_> {
		unsafe { PeView::module(self.dll_base.cast()) }
	}
}

pub trait ExportedFnRaw {
	fn exported_fn_raw(&self, name: &str) -> Result<*const ()>;
}
impl ExportedFnRaw for LdrDataEntry {
	fn exported_fn_raw(&self, name: &str) -> Result<*const ()> {
		trace!("looking up export: {name}");
		let p = self.pe();
		trace!("found pe");
		let init_fn = p.get_export(name).map_err(Error::pe("pe export"))?;
		trace!("export found");
		let init_or = match init_fn {
			Export::Symbol(s) => self
				.pe()
				.derva::<u8>(*s)
				.map_err(Error::pe("pe export derva"))?,
			Export::Forward(_) => return Err(Error::PeSanity("forwards are not supported")),
		};
		Ok(init_or as *const _ as *const ())
	}
}
