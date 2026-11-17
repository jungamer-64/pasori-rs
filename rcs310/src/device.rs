//! USB identity of the supported readers and their initial register values.
//!
//! The product ID and `bDeviceSubClass` select the reader family. Within a
//! family, `bcdDevice` and register bits that initialization reads select the
//! register values to write and the product. The values are those that Sony's
//! `Sonyddpu` driver package (NFC Port 5.4.8.6) writes for the same
//! observations; other combinations are rejected rather than guessed.

/// Sony's USB vendor ID.
pub const VENDOR_ID: u16 = 0x054c;

/// USB device descriptor fields that identify the reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    /// `idVendor`.
    pub vendor_id: u16,
    /// `idProduct`.
    pub product_id: u16,
    /// `bDeviceSubClass`.
    pub device_subclass: u8,
    /// `bcdDevice`.
    pub release: u16,
}

/// Reader product established by initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Product {
    /// RC-S310 with `bDeviceSubClass` 1, which Sony's tools name RC-S310(ED2).
    Rcs310Ed2,
    /// RC-S310.
    Rcs310,
    /// RC-S320.
    Rcs320,
    /// RC-S600, which shares the RC-S320 product ID.
    Rcs600,
}

/// Reader family selected from the descriptor before any command is sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    /// Product ID `006C`, subclass 1. Initialization writes no registers.
    Rcs310Ed2,
    /// Product ID `006C`, subclass 0.
    Rcs310,
    /// Product ID `01BB`, subclass 0: RC-S320 and RC-S600.
    Rcs320,
}

impl Family {
    pub(crate) fn identify(descriptor: Descriptor) -> Option<Self> {
        if descriptor.vendor_id != VENDOR_ID {
            return None;
        }
        match (descriptor.product_id, descriptor.device_subclass) {
            (0x006c, 1) => Some(Self::Rcs310Ed2),
            (0x006c, 0) => Some(Self::Rcs310),
            (0x01bb, 0) => Some(Self::Rcs320),
            _ => None,
        }
    }
}

/// Register observations for which no initial register values are known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Variant {
    /// `bcdDevice`.
    pub release: u16,
    /// Value of register `82`.
    pub register_82: u8,
    /// Value of register `87`, read only by the RC-S320 family.
    pub register_87: Option<u8>,
}

/// Register `82` bit set on readers whose values the driver names `o`.
const OUTPUT: u8 = 0x20;
/// Register `82` bit selecting the first `H` of an RC-S320 family name.
const HIGH_82: u8 = 0x10;
/// Register `87` bit selecting the second `H` of an RC-S320 family name.
const HIGH_87: u8 = 0x08;

/// Address and value pairs, in write order.
const RCS310_0118: &[u8] = &[
    0x89, 0x13, 0x25, 0xf0, 0xa0, 0x02, 0xa1, 0x00, 0xa2, 0x89, 0xa3, 0x10, 0xa4, 0x03, 0xa5, 0x89,
    0xa6, 0x10,
];
const RCS310_0121: &[u8] = &[
    0x89, 0x11, 0x25, 0xf0, 0xa0, 0x02, 0xa1, 0x00, 0xa2, 0x89, 0xa3, 0x10, 0xa4, 0x03, 0xa5, 0x89,
    0xa6, 0x10,
];
const REGISTER_25: &[u8] = &[0x25, 0x58];

/// Register values and product for an RC-S310 with register `82`.
pub(crate) fn rcs310(release: u16, register_82: u8) -> Option<(&'static [u8], Product)> {
    if register_82 & OUTPUT == 0 {
        return None;
    }
    match release {
        0x0118 => Some((RCS310_0118, Product::Rcs310)),
        0x0121 | 0x0122 => Some((RCS310_0121, Product::Rcs310)),
        _ => None,
    }
}

/// Register values and product for the RC-S320 family with registers `82`
/// and `87`.
pub(crate) fn rcs320(
    release: u16,
    register_82: u8,
    register_87: u8,
) -> Option<(&'static [u8], Product)> {
    if release != 0x0128 {
        return None;
    }
    let output = register_82 & OUTPUT != 0;
    let first = register_82 & HIGH_82 != 0;
    let second = register_87 & HIGH_87 != 0;
    match (output, first, second) {
        (false, false, false) => Some((REGISTER_25, Product::Rcs320)),
        (true, false, false) => Some((REGISTER_25, Product::Rcs600)),
        (true, true, false) => Some((RCS310_0121, Product::Rcs320)),
        (true, true, true) => Some((RCS310_0121, Product::Rcs600)),
        _ => None,
    }
}
