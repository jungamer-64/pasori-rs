//! Control of a Port-400 reader over its USB bulk endpoints.
//!
//! The caller owns device discovery and supplies an exclusive
//! [`Transport`](transport::Transport). A reader opens a Transparent Session
//! and carries FeliCa packets or ISO-DEP blocks within CCID Escape.
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;

mod apdu;
pub mod reader;
pub mod transport;
