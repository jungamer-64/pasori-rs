//! NFC-B discovery options of the RC-S956 reader.

/// RF tuning table from the attached reader's configuration image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RfProfile {
    /// Use the standard Type B tuning table (table 3).
    #[default]
    Standard,
    /// Use the alternate Type B tuning table (table 5).
    Alternate,
}

/// Configuration for discovery of a single NFC-B target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollOptions {
    /// RF tuning profile chosen for the attached reader.
    pub profile: RfProfile,
    /// Application Family Identifier. Zero requests all families.
    pub afi: u8,
}
