//! Port-100 host framing, reader initialization, and FeliCa packet exchange.
//!
//! The Port-100 chip, used in the RC-S380, transfers RF frames whose
//! technology, bit rate and framing the host configures. This crate selects
//! FeliCa cards and carries their packets. Transactions are exclusive and are
//! never automatically replayed after a transport failure.
#![no_std]
#![forbid(unsafe_code)]
// Wire fields are narrower than host sizes; every narrowing names its bound.
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;

pub mod reader;
pub mod transport;
pub mod wire;
