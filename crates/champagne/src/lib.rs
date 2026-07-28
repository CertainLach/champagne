extern crate self as champagne;

pub use champagne_kernel::{peb::VirtualPeb, tib::VirtualTib};
pub use champagne_loader::{
	Error, Result,
	manual_map::{FinishedPeImage, PeImage},
};
pub use champagne_winapi::ldr::override_import;
