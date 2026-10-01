extern crate self as champagne;

pub use champagne_loader::{
	Error, Result,
	manual_map::{FinishedPeImage, PeImage},
};
pub use champagne_winapi::ldr::override_import;

#[cfg(not(windows))]
pub mod unix {
	pub use champagne_kernel::{
		peb::unix::VirtualPeb,
		thread::unix::HostThread,
		tib::unix::{EnteredVirtualTib, VirtualTib},
	};
}
