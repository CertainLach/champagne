macro_rules! assert_size {
	($ty:ty, $size:expr) => {
		const _: () = assert!(std::mem::size_of::<$ty>() == $size);
	};
}

macro_rules! assert_offset {
	($ty:ty, $field:ident, $offset:expr) => {
		const _: () = assert!(std::mem::offset_of!($ty, $field) == $offset);
	};
}

pub(crate) use assert_offset;
pub(crate) use assert_size;

pub mod critical_section;
pub mod event;
pub mod ldr;
pub mod object;
pub mod peb;
pub mod thread;
pub mod tib;
