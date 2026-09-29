use champagne_kernel::critical_section::CriticalSectionPtr;
use champagne_macros::winfn;

#[winfn(alias(InitializeCriticalSection))]
fn InitializeCriticalSectionAndSpinCount(mut cs: CriticalSectionPtr, spin: u32) -> i32 {
	if cs.is_null() {
		return 0;
	}
	cs.init(spin);
	1
}

#[winfn]
fn InitializeCriticalSectionEx(mut cs: CriticalSectionPtr, spin: u32, _flags: u32) -> i32 {
	if cs.is_null() {
		return 0;
	}
	cs.init(spin);
	1
}

#[winfn]
fn EnterCriticalSection(cs: CriticalSectionPtr) {
	if cs.is_null() {
		return;
	}
	cs.enter();
}

#[winfn]
unsafe fn LeaveCriticalSection(cs: CriticalSectionPtr) {
	if cs.is_null() {
		return;
	}
	unsafe { cs.leave() };
}

#[winfn]
unsafe fn DeleteCriticalSection(mut cs: CriticalSectionPtr) {
	if cs.is_null() {
		return;
	}
	unsafe { cs.delete() };
}
