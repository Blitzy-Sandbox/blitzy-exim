//! # exim-spool
//!
//! Spool file I/O crate for the Exim MTA Rust rewrite. Provides byte-level
//! compatible reading and writing of Exim spool `-H` (header/metadata) and
//! `-D` (data) files, message ID generation, and spool format constants.
//!
//! This crate replaces the C modules `spool_in.c`, `spool_out.c`, and
//! `spool_mbox.c`.

pub mod format;
pub mod message_id;
