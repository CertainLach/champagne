use std::arch::naked_asm;
use std::ffi::c_void;
use std::mem::offset_of;
use std::ptr::null;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};

use champagne_kernel::peb::PebLike as _;
use champagne_kernel::tib::get_tib;
use champagne_macros::winfn;
use tracing::warn;

const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

const CONTEXT_FULL: u32 = 0x10000B;
const XMM_SAVE_OFFSET: usize = 0xA0;

const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

#[repr(C, align(16))]
pub struct Context {
	pub p1_home: u64,
	pub p2_home: u64,
	pub p3_home: u64,
	pub p4_home: u64,
	pub p5_home: u64,
	pub p6_home: u64,
	pub context_flags: u32,
	pub mx_csr: u32,
	pub seg_cs: u16,
	pub seg_ds: u16,
	pub seg_es: u16,
	pub seg_fs: u16,
	pub seg_gs: u16,
	pub seg_ss: u16,
	pub eflags: u32,
	pub dr0: u64,
	pub dr1: u64,
	pub dr2: u64,
	pub dr3: u64,
	pub dr6: u64,
	pub dr7: u64,
	pub rax: u64,
	pub rcx: u64,
	pub rdx: u64,
	pub rbx: u64,
	pub rsp: u64,
	pub rbp: u64,
	pub rsi: u64,
	pub rdi: u64,
	pub r8: u64,
	pub r9: u64,
	pub r10: u64,
	pub r11: u64,
	pub r12: u64,
	pub r13: u64,
	pub r14: u64,
	pub r15: u64,
	pub rip: u64,
	pub flt_save: [u8; 512],
	pub vector_register: [u128; 26],
	pub vector_control: u64,
	pub debug_control: u64,
	pub last_branch_to_rip: u64,
	pub last_branch_from_rip: u64,
	pub last_exception_to_rip: u64,
	pub last_exception_from_rip: u64,
}
const _: () = assert!(size_of::<Context>() == 0x4D0);
const _: () = assert!(offset_of!(Context, context_flags) == 0x30);
const _: () = assert!(offset_of!(Context, rax) == 0x78);
const _: () = assert!(offset_of!(Context, rsp) == 0x98);
const _: () = assert!(offset_of!(Context, rip) == 0xF8);
const _: () = assert!(offset_of!(Context, flt_save) == 0x100);
const _: () = assert!(offset_of!(Context, vector_register) == 0x300);

impl Context {
	fn int_reg(&mut self, index: u8) -> &mut u64 {
		match index {
			0 => &mut self.rax,
			1 => &mut self.rcx,
			2 => &mut self.rdx,
			3 => &mut self.rbx,
			4 => &mut self.rsp,
			5 => &mut self.rbp,
			6 => &mut self.rsi,
			7 => &mut self.rdi,
			8 => &mut self.r8,
			9 => &mut self.r9,
			10 => &mut self.r10,
			11 => &mut self.r11,
			12 => &mut self.r12,
			13 => &mut self.r13,
			14 => &mut self.r14,
			_ => &mut self.r15,
		}
	}
}

#[repr(C)]
pub struct ExceptionRecord {
	pub exception_code: u32,
	pub exception_flags: u32,
	pub exception_record: *mut ExceptionRecord,
	pub exception_address: *mut c_void,
	pub number_parameters: u32,
	pub reserved: u32,
	pub exception_information: [usize; 15],
}
const _: () = assert!(size_of::<ExceptionRecord>() == 152);

#[repr(C)]
pub struct ExceptionPointers {
	pub exception_record: *mut ExceptionRecord,
	pub context_record: *mut Context,
}

fn exception_name(code: u32) -> &'static str {
	match code {
		0xC0000005 => "ACCESS_VIOLATION",
		0xC000001D => "ILLEGAL_INSTRUCTION",
		0xC0000025 => "NONCONTINUABLE_EXCEPTION",
		0xC0000026 => "INVALID_DISPOSITION",
		0xC000008C => "ARRAY_BOUNDS_EXCEEDED",
		0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
		0xC00000FD => "STACK_OVERFLOW",
		0xC0000409 => "STACK_BUFFER_OVERRUN (/GS cookie check failed)",
		0xC0000417 => "INVALID_CRT_PARAMETER",
		0xE06D7363 => "C++ exception",
		_ => "unknown",
	}
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeFunction {
	pub begin_address: u32,
	pub end_address: u32,
	pub unwind_info_address: u32,
}

#[repr(C)]
struct UnwindInfo {
	version_flags: u8,
	size_of_prolog: u8,
	count_of_codes: u8,
	frame_register_offset: u8,
}

impl UnwindInfo {
	fn version(&self) -> u8 {
		self.version_flags & 0x7
	}
	fn flags(&self) -> u8 {
		self.version_flags >> 3
	}
	fn frame_register(&self) -> u8 {
		self.frame_register_offset & 0xF
	}
	fn frame_offset(&self) -> u64 {
		(self.frame_register_offset >> 4) as u64 * 16
	}
	unsafe fn codes(&self) -> &[u16] {
		unsafe {
			slice::from_raw_parts(
				(self as *const Self).add(1).cast::<u16>(),
				self.count_of_codes as usize,
			)
		}
	}
	unsafe fn tail(&self) -> *const u32 {
		let padded = (self.count_of_codes as usize + 1) & !1;
		unsafe {
			(self as *const Self)
				.add(1)
				.cast::<u16>()
				.add(padded)
				.cast::<u32>()
		}
	}
}

fn code_offset(code: u16) -> u8 {
	(code & 0xFF) as u8
}
fn code_op(code: u16) -> u8 {
	((code >> 8) & 0xF) as u8
}
fn code_info(code: u16) -> u8 {
	((code >> 12) & 0xF) as u8
}

fn code_slots(code: u16) -> usize {
	match code_op(code) {
		UWOP_ALLOC_LARGE => {
			if code_info(code) == 0 {
				2
			} else {
				3
			}
		}
		UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 | UWOP_EPILOG => 2,
		UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
		_ => 1,
	}
}

fn exception_table(base: usize, size_of_image: usize) -> Option<&'static [RuntimeFunction]> {
	let dos = base as *const u8;
	if unsafe { dos.cast::<u16>().read_unaligned() } != 0x5A4D {
		return None;
	}
	let lfanew = unsafe { dos.add(0x3C).cast::<u32>().read_unaligned() } as usize;
	if lfanew + 0x18 >= size_of_image {
		return None;
	}
	let nt = unsafe { dos.add(lfanew) };
	if unsafe { nt.cast::<u32>().read_unaligned() } != 0x4550 {
		return None;
	}
	let optional = unsafe { nt.add(0x18) };
	let magic = unsafe { optional.cast::<u16>().read_unaligned() };
	if magic != 0x20B {
		return None;
	}
	let data_dir = unsafe { optional.add(112) };
	let entry = unsafe {
		data_dir
			.add(IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8)
			.cast::<[u32; 2]>()
			.read_unaligned()
	};
	let (rva, size) = (entry[0] as usize, entry[1] as usize);
	if rva == 0 || size == 0 || rva + size > size_of_image {
		return None;
	}
	Some(unsafe {
		slice::from_raw_parts(
			(base + rva) as *const RuntimeFunction,
			size / size_of::<RuntimeFunction>(),
		)
	})
}

fn lookup(pc: usize) -> Option<(usize, &'static RuntimeFunction)> {
	let peb = get_tib().get_peb();
	let entry = peb.find_entry_by_pc(pc)?;
	let base = entry.base() as usize;
	let table = exception_table(base, entry.size_of_image())?;
	let rva = (pc - base) as u32;
	let index = table
		.binary_search_by(|f| {
			if f.end_address <= rva {
				std::cmp::Ordering::Less
			} else if f.begin_address > rva {
				std::cmp::Ordering::Greater
			} else {
				std::cmp::Ordering::Equal
			}
		})
		.ok()?;
	Some((base, &table[index]))
}

#[winfn]
fn RtlPcToFileHeader(pc: *mut c_void, base_of_image: *mut *mut c_void) -> *mut c_void {
	let peb = get_tib().get_peb();
	let found = peb
		.find_entry_by_pc(pc as usize)
		.map(|e| e.base().cast_mut().cast::<c_void>())
		.unwrap_or(std::ptr::null_mut());
	if !base_of_image.is_null() {
		unsafe { base_of_image.write(found) };
	}
	found
}

#[winfn]
fn RtlLookupFunctionEntry(
	control_pc: u64,
	image_base: *mut u64,
	_history: *mut c_void,
) -> *const RuntimeFunction {
	match lookup(control_pc as usize) {
		Some((base, function)) => {
			if !image_base.is_null() {
				unsafe { image_base.write(base as u64) };
			}
			function
		}
		None => {
			if !image_base.is_null() {
				unsafe { image_base.write(0) };
			}
			null()
		}
	}
}

#[winfn]
fn RtlVirtualUnwind(
	handler_type: u32,
	image_base: u64,
	control_pc: u64,
	function_entry: *const RuntimeFunction,
	context: *mut Context,
	handler_data: *mut *mut c_void,
	establisher_frame: *mut u64,
	_context_pointers: *mut c_void,
) -> *const c_void {
	if function_entry.is_null() || context.is_null() {
		return null();
	}
	unsafe {
		virtual_unwind(
			handler_type,
			image_base,
			control_pc,
			function_entry,
			&mut *context,
			handler_data,
			establisher_frame,
		)
	}
}

unsafe fn virtual_unwind(
	handler_type: u32,
	image_base: u64,
	control_pc: u64,
	mut function_entry: *const RuntimeFunction,
	context: &mut Context,
	handler_data: *mut *mut c_void,
	establisher_frame: *mut u64,
) -> *const c_void {
	let mut frame = context.rsp;
	for _ in 0..32 {
		let function = unsafe { &*function_entry };
		let info =
			unsafe { &*((image_base + function.unwind_info_address as u64) as *const UnwindInfo) };
		if info.version() > 2 {
			warn!("unsupported unwind info version {}", info.version());
			return null();
		}

		let prolog_offset = control_pc.wrapping_sub(image_base + function.begin_address as u64);
		if info.frame_register() != 0 {
			frame = *context.int_reg(info.frame_register()) - info.frame_offset();
		}

		let codes = unsafe { info.codes() };
		let mut i = 0usize;
		while i < codes.len() {
			let code = codes[i];
			let slots = code_slots(code);
			if code_offset(code) as u64 > prolog_offset {
				i += slots;
				continue;
			}
			let op_info = code_info(code);
			match code_op(code) {
				UWOP_PUSH_NONVOL => {
					*context.int_reg(op_info) = unsafe { (context.rsp as *const u64).read() };
					context.rsp += 8;
				}
				UWOP_ALLOC_LARGE => {
					context.rsp += if op_info == 0 {
						codes[i + 1] as u64 * 8
					} else {
						codes[i + 1] as u64 | (codes[i + 2] as u64) << 16
					};
				}
				UWOP_ALLOC_SMALL => context.rsp += (op_info as u64 + 1) * 8,
				UWOP_SET_FPREG => context.rsp = frame,
				UWOP_SAVE_NONVOL => {
					let at = frame + codes[i + 1] as u64 * 8;
					*context.int_reg(op_info) = unsafe { (at as *const u64).read() };
				}
				UWOP_SAVE_NONVOL_FAR => {
					let at = frame + (codes[i + 1] as u64 | (codes[i + 2] as u64) << 16);
					*context.int_reg(op_info) = unsafe { (at as *const u64).read() };
				}
				UWOP_PUSH_MACHFRAME => {
					let at = context.rsp + if op_info != 0 { 8 } else { 0 };
					context.rip = unsafe { (at as *const u64).read() };
					context.rsp = unsafe { ((at + 24) as *const u64).read() };
					if !establisher_frame.is_null() {
						unsafe { establisher_frame.write(frame) };
					}
					return null();
				}
				UWOP_SAVE_XMM128 | UWOP_SAVE_XMM128_FAR | UWOP_EPILOG => {}
				other => warn!("unknown unwind op {other}"),
			}
			i += slots;
		}

		if info.flags() & UNW_FLAG_CHAININFO == 0 {
			context.rip = unsafe { (context.rsp as *const u64).read() };
			context.rsp += 8;
			if !establisher_frame.is_null() {
				unsafe { establisher_frame.write(frame) };
			}
			let wanted = if handler_type == 1 {
				UNW_FLAG_EHANDLER
			} else {
				UNW_FLAG_UHANDLER
			};
			if handler_type != 0 && info.flags() & wanted != 0 {
				let tail = unsafe { info.tail() };
				let handler = image_base + unsafe { tail.read_unaligned() } as u64;
				if !handler_data.is_null() {
					unsafe { handler_data.write(tail.add(1).cast_mut().cast()) };
				}
				return handler as *const c_void;
			}
			return null();
		}
		function_entry = unsafe { info.tail().cast::<RuntimeFunction>() };
	}
	warn!("unwind chain too deep");
	null()
}

#[winfn]
#[unsafe(naked)]
unsafe fn RtlCaptureContext(context: *mut Context) {
	naked_asm!(
		"mov [rcx + {rax}], rax",
		"mov [rcx + {rcx}], rcx",
		"mov [rcx + {rdx}], rdx",
		"mov [rcx + {rbx}], rbx",
		"mov [rcx + {rbp}], rbp",
		"mov [rcx + {rsi}], rsi",
		"mov [rcx + {rdi}], rdi",
		"mov [rcx + {r8}], r8",
		"mov [rcx + {r9}], r9",
		"mov [rcx + {r10}], r10",
		"mov [rcx + {r11}], r11",
		"mov [rcx + {r12}], r12",
		"mov [rcx + {r13}], r13",
		"mov [rcx + {r14}], r14",
		"mov [rcx + {r15}], r15",
		"movups [rcx + {xmm} + 0x60], xmm6",
		"movups [rcx + {xmm} + 0x70], xmm7",
		"movups [rcx + {xmm} + 0x80], xmm8",
		"movups [rcx + {xmm} + 0x90], xmm9",
		"movups [rcx + {xmm} + 0xA0], xmm10",
		"movups [rcx + {xmm} + 0xB0], xmm11",
		"movups [rcx + {xmm} + 0xC0], xmm12",
		"movups [rcx + {xmm} + 0xD0], xmm13",
		"movups [rcx + {xmm} + 0xE0], xmm14",
		"movups [rcx + {xmm} + 0xF0], xmm15",
		"mov rax, [rsp]",
		"mov [rcx + {rip}], rax",
		"lea rax, [rsp + 8]",
		"mov [rcx + {rsp}], rax",
		"mov word ptr [rcx + {seg_cs}], cs",
		"mov word ptr [rcx + {seg_ss}], ss",
		"pushfq",
		"pop rax",
		"mov [rcx + {eflags}], eax",
		"stmxcsr [rcx + {mx_csr}]",
		"mov dword ptr [rcx + {context_flags}], {context_full}",
		"ret",
		rax = const offset_of!(Context, rax),
		rcx = const offset_of!(Context, rcx),
		rdx = const offset_of!(Context, rdx),
		rbx = const offset_of!(Context, rbx),
		rbp = const offset_of!(Context, rbp),
		rsi = const offset_of!(Context, rsi),
		rdi = const offset_of!(Context, rdi),
		r8 = const offset_of!(Context, r8),
		r9 = const offset_of!(Context, r9),
		r10 = const offset_of!(Context, r10),
		r11 = const offset_of!(Context, r11),
		r12 = const offset_of!(Context, r12),
		r13 = const offset_of!(Context, r13),
		r14 = const offset_of!(Context, r14),
		r15 = const offset_of!(Context, r15),
		rip = const offset_of!(Context, rip),
		rsp = const offset_of!(Context, rsp),
		xmm = const offset_of!(Context, flt_save) + XMM_SAVE_OFFSET,
		seg_cs = const offset_of!(Context, seg_cs),
		seg_ss = const offset_of!(Context, seg_ss),
		eflags = const offset_of!(Context, eflags),
		mx_csr = const offset_of!(Context, mx_csr),
		context_flags = const offset_of!(Context, context_flags),
		context_full = const CONTEXT_FULL,
	)
}

#[winfn]
fn UnhandledExceptionFilter(info: *mut ExceptionPointers) -> i32 {
	if info.is_null() {
		warn!("unhandled exception with no information");
		return 1;
	}
	let info = unsafe { &*info };
	if !info.exception_record.is_null() {
		let record = unsafe { &*info.exception_record };
		warn!(
			"unhandled exception {:#010x} ({}) at {:?}",
			record.exception_code,
			exception_name(record.exception_code),
			record.exception_address,
		);
		for i in 0..record.number_parameters.min(15) as usize {
			warn!("  parameter {i}: {:#x}", record.exception_information[i]);
		}
	}
	if !info.context_record.is_null() {
		walk(unsafe { std::ptr::read(info.context_record) }, 24);
	}
	1
}
#[winfn]
fn SetUnhandledExceptionFilter(filter: *mut c_void) -> *mut c_void {
	static FILTER: AtomicUsize = AtomicUsize::new(0);
	FILTER.swap(filter as usize, Ordering::Relaxed) as *mut c_void
}
#[winfn]
fn RaiseException(code: u32, flags: u32, _n_args: u32, _args: *const usize) {
	panic!("todo: seh: exception {code:#x} raised with flags {flags:#x}");
}

pub fn backtrace(limit: usize) {
	let mut context = unsafe { std::mem::zeroed::<Context>() };
	unsafe { RtlCaptureContext(&mut context) };
	walk(context, limit)
}

fn describe(pc: usize) -> String {
	let peb = get_tib().get_peb();
	match peb.find_entry_by_pc(pc) {
		Some(entry) => format!("{}+{:#x}", entry.base_name(), pc - entry.base() as usize),
		None => format!("{pc:#x}"),
	}
}

fn walk(mut context: Context, limit: usize) {
	for depth in 0..limit {
		let Some((image_base, function)) = lookup(context.rip as usize) else {
			warn!(
				"  frame {depth}: {} (no unwind info)",
				describe(context.rip as usize)
			);
			break;
		};
		warn!("  frame {depth}: {}", describe(context.rip as usize));
		let mut frame = 0u64;
		unsafe {
			virtual_unwind(
				0,
				image_base as u64,
				context.rip,
				function,
				&mut context,
				std::ptr::null_mut(),
				&mut frame,
			)
		};
		if context.rip == 0 {
			break;
		}
	}
}
