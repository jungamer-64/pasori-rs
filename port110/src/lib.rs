//! Port-110 BLE reader framing, initialization, and FeliCa exchange.
//!
//! Port-110 readers, such as the RC-S390, carry host frames over a Bluetooth
//! LE GATT service. This crate frames commands, splits them into GATT writes,
//! receives the reader's indications, initializes the reader, and selects
//! FeliCa cards and carries their packets. Transactions are exclusive and
//! are never automatically replayed after a transport failure.
#![no_std]
#![forbid(unsafe_code)]
// Wire fields are narrower than host sizes; every narrowing names its bound.
#![deny(clippy::cast_possible_truncation)]

extern crate alloc;

pub mod reader;
pub mod transport;
pub mod wire;
