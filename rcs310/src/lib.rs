//! RC-S310 and RC-S320 host framing, reader initialization, and FeliCa
//! packet exchange.
//!
//! These readers carry FeliCa packets only. Transactions are exclusive and
//! are never automatically replayed after a transport failure.
#![no_std]
#![forbid(unsafe_code)]
// Wire fields are narrower than host sizes; every narrowing names its bound.
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;

pub mod device;
pub mod reader;
pub mod transport;
pub mod wire;
