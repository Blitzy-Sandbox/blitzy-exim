#![deny(unsafe_code)]
// exim-core — Main binary crate for Exim Mail Transfer Agent (Rust rewrite)
//
// This is the entry point. Modules will be expanded as implementation proceeds.

pub mod cli;
pub mod context;
pub mod daemon;
pub mod modes;
pub mod process;
pub mod queue_runner;
pub mod signal;

fn main() {
    // Stub: will be replaced by implementation agent
    // For now, just validate that CLI parsing compiles.
    let _cli = cli::parse_args();
    let _mode = cli::determine_mode(&_cli);
}
