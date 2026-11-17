//! Scripted reader transports for wire-level tests of the reader layers and
//! `pasori`.
//!
//! Responses are built independently of the production frame encoders. The
//! scripts model command and response contracts, not physical device timing.

pub mod rcs310;
pub mod rcs956;
