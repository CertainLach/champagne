use champagne_macros::winfn;

#[winfn]
fn EncodePointer(i: usize) -> usize {
	!i
}
