use std::time::{SystemTime, UNIX_EPOCH};

use champagne_macros::winfn;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::peb::{ERROR_INVALID_PARAMETER, SetLastError};

const TIME_ZONE_ID_UNKNOWN: u32 = 0;
const SECONDS_1601_TO_1970: u64 = 11644473600;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SystemTimeW {
	year: u16,
	month: u16,
	day_of_week: u16,
	day: u16,
	hour: u16,
	minute: u16,
	second: u16,
	milliseconds: u16,
}
const _: () = assert!(size_of::<SystemTimeW>() == 16);

#[repr(C)]
struct TimeZoneInformation {
	bias: i32,
	standard_name: [u16; 32],
	standard_date: SystemTimeW,
	standard_bias: i32,
	daylight_name: [u16; 32],
	daylight_date: SystemTimeW,
	daylight_bias: i32,
}
const _: () = assert!(size_of::<TimeZoneInformation>() == 172);

fn system_time_from_unix(secs: i64, milliseconds: u16) -> SystemTimeW {
	let at = OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
	SystemTimeW {
		year: at.year() as u16,
		month: u8::from(at.month()) as u16,
		day_of_week: at.weekday().number_days_from_sunday() as u16,
		day: at.day() as u16,
		hour: at.hour() as u16,
		minute: at.minute() as u16,
		second: at.second() as u16,
		milliseconds,
	}
}

fn unix_from_system_time(at: &SystemTimeW) -> Option<i64> {
	let date = Date::from_calendar_date(
		at.year as i32,
		Month::try_from(at.month as u8).ok()?,
		at.day as u8,
	)
	.ok()?;
	let time = Time::from_hms(at.hour as u8, at.minute as u8, at.second as u8).ok()?;
	Some(
		PrimitiveDateTime::new(date, time)
			.assume_utc()
			.unix_timestamp(),
	)
}

fn now_unix() -> (i64, u16) {
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	(now.as_secs() as i64, now.subsec_millis() as u16)
}

#[winfn]
#[alias(GetSystemTime)]
fn GetLocalTime(out: *mut SystemTimeW) {
	if out.is_null() {
		return;
	}
	let (secs, millis) = now_unix();
	unsafe { out.write(system_time_from_unix(secs, millis)) };
}

#[winfn]
fn GetTimeZoneInformation(info: *mut TimeZoneInformation) -> u32 {
	if !info.is_null() {
		unsafe { info.write_bytes(0, 1) };
	}
	TIME_ZONE_ID_UNKNOWN
}

#[winfn]
fn SystemTimeToFileTime(time: *const SystemTimeW, out: *mut u64) -> i32 {
	if time.is_null() || out.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let time = unsafe { &*time };
	let Some(secs) = unix_from_system_time(time) else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	};
	let ticks =
		(secs + SECONDS_1601_TO_1970 as i64) * 10_000_000 + time.milliseconds as i64 * 10_000;
	unsafe { out.write_unaligned(ticks as u64) };
	1
}

#[winfn]
fn FileTimeToSystemTime(file_time: *const u64, out: *mut SystemTimeW) -> i32 {
	if file_time.is_null() || out.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	let ticks = unsafe { file_time.read_unaligned() };
	let secs = (ticks / 10_000_000) as i64 - SECONDS_1601_TO_1970 as i64;
	let millis = (ticks % 10_000_000 / 10_000) as u16;
	unsafe { out.write(system_time_from_unix(secs, millis)) };
	1
}

#[winfn]
#[alias(TzSpecificLocalTimeToSystemTime)]
fn SystemTimeToTzSpecificLocalTime(
	_zone: *const TimeZoneInformation,
	input: *const SystemTimeW,
	out: *mut SystemTimeW,
) -> i32 {
	if input.is_null() || out.is_null() {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	unsafe { out.write(*input) };
	1
}

#[winfn]
fn GetSystemTimeAsFileTime(out: *mut u64) {
	if out.is_null() {
		return;
	}
	let unix = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	let ticks =
		(unix.as_secs() + SECONDS_1601_TO_1970) * 10_000_000 + unix.subsec_nanos() as u64 / 100;
	unsafe { out.write_unaligned(ticks) };
}
