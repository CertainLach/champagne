use std::env;
use std::process::exit;

use champagne::unix::{VirtualPeb, VirtualTib};
use champagne_mpengine::MpEngine;

fn main() {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| "warn,champagne_mpengine=info".parse().unwrap()),
		)
		.init();

	let args: Vec<String> = env::args().skip(1).collect();
	if args.is_empty() {
		eprintln!("usage: mpclient [filenames...]");
		exit(1);
	}

	champagne_mpengine::install_segv_handler();

	let peb = VirtualPeb::new();
	let tib = VirtualTib::new(&peb);
	let _entered = tib.enter();

	let engine = match MpEngine::open(&peb, "engine") {
		Ok(e) => e,
		Err(e) => {
			eprintln!("failed to load engine: {e}");
			exit(1);
		}
	};

	for path in &args {
		engine.scan(path);
	}
}
