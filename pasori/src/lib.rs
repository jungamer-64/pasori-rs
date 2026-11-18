//! NFC card protocols for PaSoRi readers.
//!
//! The reader layers activate targets and transfer frames: [`rcs956`] for
//! RC-S956 readers, [`rcs310`] for the FeliCa-only RC-S310 and RC-S320, and
//! [`port100`] for FeliCa on Port-100 readers. This crate runs the card
//! command protocols over those transfers; its FeliCa protocols accept any
//! [`felica_packet::Selection`].
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub use felica_packet;
pub use iso14443;
pub use port100;
pub use rcs310;
pub use rcs956;

pub mod falp;
pub mod felica;
pub mod isodep;
pub mod ndef;
pub mod type1;
pub mod type2;
