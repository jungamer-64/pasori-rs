//! NFC card protocols for PaSoRi readers.
//!
//! The RC-S956 chip layer ([`rcs956`]) activates targets and transfers
//! frames; this crate runs the card command protocols over those transfers.
//! Its FeliCa protocols accept any [`felica_packet::Selection`].
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub use felica_packet;
pub use rcs956;

pub mod falp;
pub mod felica;
pub mod isodep;
pub mod ndef;
pub mod type1;
pub mod type2;
