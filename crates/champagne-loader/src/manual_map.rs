use std::collections::BTreeSet;
use std::fs::File;

use std::mem::{ManuallyDrop, transmute};
use std::path::Path;
use std::ptr::{addr_of, null};

use std::process;

use champagne_kernel::ldr::OwnedLdrData;
use champagne_kernel::peb::{PebLike, get_peb};
use memmap2::{Mmap, MmapOptions};
use nt_string::unicode_string::NtUnicodeString;
use pelite::image::{
	IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
	IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pelite::pe64::{GetProcAddress as _, Pe as _, PeFile};
use pelite::util::AlignTo as _;
use pelite::{Export, Import};
use region::Protection;
use std::sync::atomic::Ordering;
use tracing::{debug, info, trace, warn};

#[cfg(not(windows))]
use memmap2::MmapMut;
#[cfg(not(windows))]
use std::sync::atomic::AtomicU64;

use crate::cc::KnownCcFunction;
use crate::entry::DLL_PROCESS_ATTACH;
use crate::jitreg::register_jit_code;
use crate::mkstub::make_stub;
use crate::{Error, ExportedFnRaw, Result};

#[cfg(windows)]
fn map_image(len: usize) -> Result<MmapMut> {
	Ok(MmapOptions::new().len(len).map_anon()?)
}
#[cfg(not(windows))]
fn map_image(len: usize) -> Result<MmapMut> {
	// Hardened kernel refuses to add PROT_EXEC to anon mapping, idk.

	use nix::fcntl::OFlag;
	use nix::libc::ftruncate;
	use nix::sys::mman::{shm_open, shm_unlink};
	use nix::sys::stat::Mode;
	use std::os::fd::AsRawFd as _;

	use crate::Error;
	static SHM_CTR: AtomicU64 = AtomicU64::new(0);
	let shm_name = format!(
		"/dllloader-{}-{}",
		process::id(),
		SHM_CTR.fetch_add(1, Ordering::Relaxed)
	);
	let map = shm_open(
		shm_name.as_str(),
		OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
		Mode::S_IRWXU,
	)
	.map_err(Error::ShmOpen)?;
	shm_unlink(shm_name.as_str()).map_err(Error::ShmOpen)?;

	let ft = unsafe { ftruncate(map.as_raw_fd(), len as i64) };
	if ft != 0 {
		use nix::errno::Errno;

		return Err(Error::ShmOpen(Errno::from_i32(ft)));
	}
	Ok(unsafe {
		use memmap2::MmapMut;
		MmapMut::map_mut(map.as_raw_fd()).map_err(Error::Mmap)?
	})
}

pub struct PeImage {
	image: MmapMut,
	ro_orig_image: Mmap,
	resolved_inputs: bool,
	ldr: OwnedLdrData,
}
impl PeImage {
	pub fn open(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref();
		let mut full_name = NtUnicodeString::new();
		full_name
			.try_push_str("C:\\libs\\")
			.expect("no overflow yet");
		// TODO: On windows, strip/replace drive name
		full_name
			.try_push_str(
				path.to_str()
					.ok_or_else(|| Error::sanity("path is not utf8"))?,
			)
			.map_err(|_| Error::sanity("file path is too long"))?;
		let mut base_name = NtUnicodeString::new();
		base_name
			.try_push_str(
				path.file_name()
					.ok_or_else(|| Error::sanity("no basename"))?
					.to_str()
					.expect("full path is utf8 as checked"),
			)
			.expect("full path didn't overflow");

		Self::new(full_name, base_name, File::open(path).map_err(Error::Mmap)?)
	}
	pub fn new(full_name: NtUnicodeString, base_name: NtUnicodeString, file: File) -> Result<Self> {
		let ro_orig_image = unsafe {
			MmapOptions::new()
				.map_copy_read_only(&file)
				.map_err(Error::Mmap)?
		};
		let pe = PeFile::from_bytes(&ro_orig_image).map_err(Error::pe("file view"))?;
		let pe_data = pe.to_view();

		let mut image = map_image(pe_data.len())?;
		image.copy_from_slice(&pe_data);

		info!("mapped to run = {image:?}, pe = {ro_orig_image:?}");
		let ep = match pe.optional_header().AddressOfEntryPoint {
			0 => null(),
			rva => unsafe { image.as_ptr().byte_offset(rva as isize).cast() },
		};
		let mut entry =
			OwnedLdrData::new(full_name, base_name, image.as_ptr().cast(), image.len(), ep);
		info!("adding to PEB");
		get_peb().lock().add_entry(entry.unchecked_get_pinned());
		let mut img = Self {
			image,
			ro_orig_image,
			resolved_inputs: false,
			ldr: entry,
		};

		'rebase: {
			let (mut editor, data) = img.project();

			let relocs = data.base_relocs();
			if relocs.err() == Some(pelite::Error::Null) {
				debug!("no base relocs");
				break 'rebase;
			}

			let image_base = editor.mapped_image_base() as u64;
			let orig_base = data.optional_header().ImageBase;
			let rebase_delta = image_base as i64 - orig_base.get() as i64;
			debug!("rebasing by {rebase_delta:x}");

			for block in relocs.map_err(Error::pe("relocs"))?.iter_blocks() {
				for word in block.words() {
					let rva = block.rva_of(word);
					let ty = block.type_of(word);
					if ty == IMAGE_REL_BASED_ABSOLUTE {
						trace!("absolute base {rva}");
					} else if ty == IMAGE_REL_BASED_HIGHLOW || ty == IMAGE_REL_BASED_DIR64 {
						let orig: &u64 = data.derva(rva).map_err(Error::pe("derva reloc"))?;
						let new = editor.mut_mirror(orig);
						*new = orig.wrapping_add_signed(rebase_delta);
						trace!("rebased {rva}: {orig:x} => {new:x}");
					} else {
						warn!("unknown base reloc: {ty}");
					}
				}
			}
		}
		// get_tib().get_peb().lock();

		Ok(img)
	}
	fn project(&mut self) -> (PeEditor<'_>, PeFile<'_>) {
		let pe = PeFile::from_bytes(&self.ro_orig_image).expect("validity checked in new()");
		(
			PeEditor {
				mapped_image: &mut self.image,
				dll_file: &self.ro_orig_image,
				pe,
			},
			pe,
		)
	}
	pub fn resolve_imports(
		&mut self,
		default: fn(&str, &str) -> Option<usize>,
		linker: &dyn PebLike,
	) -> Result<()> {
		let (mut editor, data) = self.project();
		let imports = data.imports();

		if imports.err() == Some(pelite::Error::Null) {
			trace!("no imports");
			self.resolved_inputs = true;
			return Ok(());
		}

		trace!("resolving imports");

		for desc in imports.map_err(Error::pe("imports"))? {
			let dll = desc.dll_name().map_err(Error::pe("import dll_name"))?;
			debug!("importing {dll}");
			let int = desc.int().map_err(Error::pe("import int"))?;
			let iat = desc.iat().map_err(Error::pe("import iat"))?;

			if int.len() != iat.len() {
				return Err(Error::PeSanity("iat int mismatch"));
			}
			let mut printed_dll_not_found_warning = BTreeSet::new();
			for (int, iat) in int.zip(iat) {
				let int = int.map_err(Error::pe("import int"))?;
				match int {
					Import::ByName { hint: _, name } => {
						let orig = iat;
						let new = editor.mut_mirror(iat);
						let mut dllstr = dll.to_str().expect("module not utf8").to_lowercase();
						if dllstr.starts_with("api-ms-win-") {
							warn!("rewriting {dllstr} => ucrtbase.dll");
							dllstr = "ucrtbase.dll".to_owned();
						}
						trace!("import {dllstr}.{name:?}");
						let namestr = name.to_str().expect("import not utf8");
						// A real module always wins
						let real = linker
							.find_entry(&dllstr)
							.map(|dll| (dll.exported_fn_raw(namestr), dll));
						*new = match real {
							Some((Ok::<_, Error>(fun), _)) => fun as u64,
							other => {
								if let Some((Err(e), _)) = &other {
									trace!("{dllstr} lacks {namestr} ({e}), trying builtins");
								} else if printed_dll_not_found_warning.insert(dllstr.to_owned()) {
									warn!("dll not mapped, using builtins: {dllstr}");
								}
								match default(&dllstr, namestr) {
									Some(v) => v as u64,
									None => {
										warn!("unresolved import, stubbing: {dllstr}:{namestr}");
										make_stub(format!(
											"function was not defined: {dllstr}:{namestr}"
										)) as usize as u64
									}
								}
							}
						};
						trace!("resolved {dll}:{name}: {orig:x} => {new:x}");
					}
					Import::ByOrdinal { ord } => {
						let orig = iat;
						let new = editor.mut_mirror(iat);
						*new = make_stub(format!("function was not defined: {dll}#ord")) as usize
							as u64;
						trace!("resolved {dll}:{ord}: {orig:x} => {new:x}");
					}
				}
			}
		}
		self.resolved_inputs = true;
		Ok(())
	}
	pub fn finish(self) -> Result<FinishedPeImage> {
		if !self.resolved_inputs {
			warn!("resolve_inputs was not called, stubbing everything");
		}
		let exec = self.image.make_read_only().map_err(Error::Mmap)?;
		let pe = PeFile::from_bytes(&self.ro_orig_image).expect("validity checked in new()");
		let section_alignment = pe.optional_header().SectionAlignment;

		for ele in pe.section_headers() {
			let mut protection = Protection::NONE;
			let chr = ele.Characteristics;

			if chr & IMAGE_SCN_MEM_EXECUTE != 0 {
				protection |= Protection::EXECUTE
			}
			if chr & IMAGE_SCN_MEM_READ != 0 {
				protection |= Protection::READ
			}
			if chr & IMAGE_SCN_MEM_WRITE != 0 {
				protection |= Protection::WRITE
			}
			let lossy_name = String::from_utf8_lossy(ele.name_bytes());
			trace!(target:"section", "protecting {lossy_name} as {protection}");

			unsafe {
				region::protect(
					exec.as_ptr().byte_offset(ele.VirtualAddress as isize),
					ele.VirtualSize.align_to(section_alignment) as usize,
					protection,
				)?
			};
		}
		// if jit {
		register_jit_code(exec.as_ptr().cast(), exec.len() as u64);

		// }

		Ok(FinishedPeImage {
			image: ManuallyDrop::new(exec),
			ro_orig_image: ManuallyDrop::new(self.ro_orig_image),
		})
	}
	fn pe(&self) -> PeFile<'_> {
		PeFile::from_bytes(&self.ro_orig_image).expect("file shouldn't be corrupted during linking")
	}
	fn mirror<T>(&self, v: &T) -> &T {
		mirror_raw(&self.image, &self.ro_orig_image, &self.pe(), v)
	}
}
impl ExportedFnRaw for PeImage {
	fn exported_fn_raw(&self, name: &str) -> Result<*const ()> {
		let init_fn = self.pe().get_export(name).map_err(Error::pe("pe export"))?;
		let init_or = match init_fn {
			Export::Symbol(s) => self
				.pe()
				.derva::<u8>(*s)
				.map_err(Error::pe("pe export derva"))?,
			Export::Forward(_) => return Err(Error::PeSanity("forwards are not supported")),
		};
		Ok(self.mirror(init_or) as *const _ as *const ())
	}
}
pub struct FinishedPeImage {
	image: ManuallyDrop<Mmap>,
	ro_orig_image: ManuallyDrop<Mmap>,
}
impl FinishedPeImage {
	fn pe(&self) -> PeFile<'_> {
		let file = PeFile::from_bytes(&*self.ro_orig_image)
			.expect("file shouldn't be corrupted during linking");
		file
	}
	fn assert_in_image<T>(&self, p: *const T) {
		let orig = p.cast::<u8>();
		let offset = unsafe { orig.offset_from(self.image.as_ptr().cast()) };
		assert!(offset > 0 && (offset as usize) < self.image.len());
	}
	fn mirror<T>(&self, v: &T) -> &T {
		mirror_raw(&self.image, &self.ro_orig_image, &self.pe(), v)
	}
	pub unsafe fn exported_fn<F: KnownCcFunction>(&self, name: &str) -> Result<F> {
		Ok(unsafe { F::from_ptr(self.exported_fn_raw(name)?) })
	}
	pub fn init_exceptions(&self) -> Result<()> {
		let exc = self.pe().exception_x64();
		if exc.err() == Some(pelite::Error::Null) {
			info!("image has no exceptions");
			return Ok(());
		}
		#[allow(clippy::never_loop)]
		for ele in exc.map_err(Error::pe("exceptions"))?.functions() {
			warn!("todo: exceptions: {:?}", ele.image());
			break;
		}
		Ok(())
	}
	fn mapped_va(&self, va: u64) -> usize {
		let rva = va - self.pe().optional_header().ImageBase.get();
		self.image.as_ptr() as usize + rva as usize
	}
	/// # Safety
	///
	/// This function executes code from the loaded library
	// TODO: windows
	#[cfg(not(windows))]
	pub unsafe fn init_static_tls(&self) -> Result<()> {
		use champagne_kernel::peb::unix::PebLikeUnixExt as _;

		let tls = self.pe().tls();
		if tls.err() == Some(pelite::Error::Null) {
			debug!("image has no tls");
			return Ok(());
		}
		let tls = tls.map_err(Error::pe("tls"))?;
		let image = tls.image();
		let template = tls.raw_data().map_err(Error::pe("tls template"))?;

		let index = get_peb().register_tls_template(template, image.SizeOfZeroFill as usize);
		unsafe { (self.mapped_va(image.AddressOfIndex) as *mut u32).write(index) };
		debug!(
			"static tls index {index}, {} bytes",
			template.len() + image.SizeOfZeroFill as usize
		);

		let mut callbacks = Vec::new();
		for callback in tls.callbacks().map_err(Error::pe("tls callbacks"))? {
			if *callback == 0 {
				break;
			}
			callbacks.push(self.mapped_va(*callback));
		}
		debug!("{} tls callbacks", callbacks.len());
		get_peb()
			.private()
			.register_tls_callbacks(self.image.as_ptr() as usize, callbacks.clone());

		for callback in callbacks {
			let callback: extern "win64" fn(*const u8, u32, *const u8) =
				unsafe { transmute(callback) };
			callback(self.image.as_ptr(), DLL_PROCESS_ATTACH, null());
		}
		Ok(())
	}
	/// # Safety
	///
	/// This function executes code from the loaded library
	pub unsafe fn call_ep_if_exists(&self) -> Result<()> {
		let peb = get_peb();
		let _loader = peb.loader_lock();
		if self.pe().optional_header().AddressOfEntryPoint != 0 {
			let ep = unsafe {
				self.image
					.as_ptr()
					.byte_offset(self.pe().optional_header().AddressOfEntryPoint as isize)
			};
			self.assert_in_image(ep);
			debug!("ep found: {ep:?}, calling it");
			let ep: extern "win64" fn(*const u8, u32, *const u8) -> i32 = unsafe { transmute(ep) };
			let ret = ep(self.image.as_ptr(), 1, null());
			if ret == 0 {
				return Err(Error::PeSanity("DLL_PROCESS_ATTACH failed"));
			}
		}
		Ok(())
	}
}
impl ExportedFnRaw for FinishedPeImage {
	fn exported_fn_raw(&self, name: &str) -> Result<*const ()> {
		let init_fn = self.pe().get_export(name).map_err(Error::pe("pe export"))?;
		let init_or = match init_fn {
			Export::Symbol(s) => self
				.pe()
				.derva::<u8>(*s)
				.map_err(Error::pe("pe export derva"))?,
			Export::Forward(_) => return Err(Error::PeSanity("forwards are not supported")),
		};
		Ok(self.mirror(init_or) as *const _ as *const ())
	}
}

struct PeEditor<'m> {
	mapped_image: &'m mut MmapMut,
	dll_file: &'m Mmap,
	pe: PeFile<'m>,
}
impl PeEditor<'_> {
	fn mapped_image_base(&self) -> usize {
		self.mapped_image.as_ptr() as usize
	}
	fn mut_mirror<T>(&mut self, v: &T) -> &mut T {
		mut_mirror_raw(self.mapped_image, self.dll_file, &self.pe, v)
	}
}

fn mut_mirror_raw<'o, T>(
	mapped_image: &'o mut [u8],
	dll_file: &[u8],
	pe: &PeFile,
	v: &T,
) -> &'o mut T {
	let orig = addr_of!(*v).cast::<u8>();
	let offset = unsafe { orig.offset_from(dll_file.as_ptr().cast()) };
	assert!(
		offset > 0 && (offset as usize) < dll_file.len(),
		"can't mirror value not from source dll file"
	);
	let rva = pe.file_offset_to_rva(offset as usize).expect("in image");
	assert!((rva as usize) < mapped_image.len(), "rva is out of mapping");
	unsafe { &mut *mapped_image.as_mut_ptr().byte_offset(rva as isize).cast() }
}
fn mirror_raw<'o, T>(mapped_image: &'o [u8], dll_file: &[u8], pe: &PeFile, v: &T) -> &'o T {
	let orig = addr_of!(*v).cast::<u8>();
	let offset = unsafe { orig.offset_from(dll_file.as_ptr().cast()) };
	assert!(
		offset > 0 && (offset as usize) < dll_file.len(),
		"can't mirror value not from source dll file"
	);
	let rva = pe.file_offset_to_rva(offset as usize).expect("in image");
	assert!((rva as usize) < mapped_image.len(), "rva is out of mapping");
	unsafe { &*mapped_image.as_ptr().byte_offset(rva as isize).cast() }
}
