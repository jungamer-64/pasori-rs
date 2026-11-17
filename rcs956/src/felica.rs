//! FeliCa RF rate selection of the RC-S956 reader.

/// RF rate selected for FeliCa polling and subsequent exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitRate {
    /// 212 kbps.
    Kbps212,
    /// 424 kbps.
    Kbps424,
}

impl BitRate {
    pub(crate) fn selector(self) -> u8 {
        match self {
            Self::Kbps212 => 1,
            Self::Kbps424 => 2,
        }
    }
}
