use std::mem::transmute;

pub trait KnownCcFunction {
	unsafe fn from_ptr(ptr: *const ()) -> Self;
}
trait Win64Function {
	fn argc() -> usize;
}
pub trait SysvFunction {
	fn argc() -> usize;
	fn as_ptr(&self) -> *const u8 {
		self as *const _ as *const u8
	}
}

macro_rules! impl_args_like {
	($count:expr; $($gen:ident)*) => {
		impl<T, $($gen,)*> Win64Function for extern "win64" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
		impl<T, $($gen,)*> KnownCcFunction for unsafe extern "win64" fn($($gen,)*) -> T {
			unsafe fn from_ptr(ptr: *const ()) -> Self {
				unsafe{transmute(ptr)}
			}
		}
		// Assuming linux here
		impl<T, $($gen,)*> SysvFunction for extern "C" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
		impl<T, $($gen,)*> SysvFunction for unsafe extern "C" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
	};
	($count:expr; $($cur:ident)* @ $c:ident $($rest:ident)*) => {
		impl_args_like!($count; $($cur)*);
		impl_args_like!($count + 1usize; $($cur)* $c @ $($rest)*);
	};
	($count:expr; $($cur:ident)* @) => {
		impl_args_like!($count; $($cur)*);
	}
}
impl_args_like! {
   0usize; @ A B C D E F G H I J K L
}
