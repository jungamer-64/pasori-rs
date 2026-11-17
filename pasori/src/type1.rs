//! NFC Forum Type 1 tag commands over an RC-S956 Type 1 selection.

use alloc::vec::Vec;
use rcs956::{
    reader::{Error, TargetExchangeError, Type1Target},
    transport::Transport,
};

/// An identified Type 1 tag. Its UID is the four-byte command address
/// returned by RID; it is scoped to this selection.
#[derive(Debug)]
pub struct Type1Tag<'a, T: Transport> {
    target: Type1Target<'a, T>,
    header_rom: [u8; 2],
    uid: [u8; 4],
}

impl<'a, T: Transport> Type1Tag<'a, T> {
    /// Request the selected tag's identity with RID. A failure ends the
    /// selection: the next selection cycles the RF field. A pending response
    /// fragment requires reader initialization.
    pub fn identify(mut target: Type1Target<'a, T>) -> Result<Self, TargetExchangeError<T::Error>> {
        let identity = match target.exchange(&[0x78, 0, 0, 0, 0, 0, 0]) {
            Ok(identity) => identity,
            Err(error) => {
                target.require_field_cycle();
                return Err(error);
            }
        };
        let [hr0, hr1, a, b, c, d] = identity.as_slice() else {
            target.require_field_cycle();
            return Err(response_error("Type 1 RID layout"));
        };
        Ok(Self {
            header_rom: [*hr0, *hr1],
            uid: [*a, *b, *c, *d],
            target,
        })
    }

    /// Four UID bytes used to address this tag.
    pub fn uid(&self) -> [u8; 4] {
        self.uid
    }

    /// The header ROM returned by RID. HR0 distinguishes static and dynamic layouts.
    pub fn header_rom(&self) -> [u8; 2] {
        self.header_rom
    }

    pub(crate) fn read_static(&mut self) -> Result<[u8; 120], TargetExchangeError<T::Error>> {
        let reply = self.command(0, 0, 0)?;
        let [hr0, _, memory @ ..] = reply.as_slice() else {
            return Err(response_error("Type 1 RALL layout"));
        };
        if *hr0 != self.header_rom[0] || !memory.starts_with(&self.uid) {
            return Err(response_error("Type 1 RALL identity"));
        }
        memory
            .try_into()
            .map_err(|_| response_error("Type 1 RALL length"))
    }

    pub(crate) fn write_byte(
        &mut self,
        address: u8,
        value: u8,
    ) -> Result<(), TargetExchangeError<T::Error>> {
        let reply = self.command(0x53, address, value)?;
        if reply != [address, value] {
            return Err(response_error("Type 1 WRITE-E echo"));
        }
        Ok(())
    }

    fn command(
        &mut self,
        code: u8,
        address: u8,
        data: u8,
    ) -> Result<Vec<u8>, TargetExchangeError<T::Error>> {
        let [a, b, c, d] = self.uid;
        self.target.exchange(&[code, address, data, a, b, c, d])
    }
}

fn response_error<E>(reason: &'static str) -> TargetExchangeError<E> {
    TargetExchangeError::Exchange(Error::Response(reason))
}
