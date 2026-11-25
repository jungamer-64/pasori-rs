use super::{Card, CardError, Error, admit_packet, append_codes};
use alloc::vec::Vec;
use felica_packet::Selection;

/// A node's two-byte key version as reported by the card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyVersion(u16);

impl KeyVersion {
    /// The reported version, or `None` for the card's FFFF marker.
    ///
    /// In a v2 reply the marker can also mean that the node lacks that key.
    pub fn value(self) -> Option<u16> {
        (self.0 != u16::MAX).then_some(self.0)
    }
}

/// Ordered key versions returned by Request Service v2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2KeyVersions {
    /// This card returns one AES version per requested node.
    Aes(Vec<KeyVersion>),
    /// This card returns separate AES and DES lists in the same node order.
    AesAndDes {
        /// AES/DES identifier reported by the product (`0x41` or `0x43`).
        identifier: u8,
        /// AES versions in request order.
        aes: Vec<KeyVersion>,
        /// DES versions in request order.
        des: Vec<KeyVersion>,
    },
}

/// Basic and optional card OS versions in their on-card BCD representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecificationVersion {
    /// Basic version, including the format's high nibble.
    pub basic: u16,
    /// Version words in card-defined option order, including reserved entries.
    pub options: Vec<u16>,
}

impl SpecificationVersion {
    /// The advertised nonzero value-limited purse option version, including the format nibble.
    /// `None` means no valid nonzero version was reported for this option.
    pub fn value_limited_purse_version(&self) -> Option<u16> {
        self.option_version(3)
    }

    /// The advertised nonzero MAC communication option version, including the format nibble.
    /// `None` means no valid nonzero version was reported for this option. Use
    /// [`Card::mac_service_properties`] to check whether an individual service has it enabled.
    pub fn mac_communication_version(&self) -> Option<u16> {
        self.option_version(4)
    }

    fn option_version(&self, index: usize) -> Option<u16> {
        let &word = self.options.get(index)?;
        let [low, high] = word.to_le_bytes();
        let digits = [high & 0x0f, low >> 4, low & 0x0f];
        (high >> 4 == 8 && word != 0x8000 && digits.into_iter().all(|digit| digit <= 9))
            .then_some(word)
    }
}

/// Value-limited purse properties reported by the selected card for a service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueLimitedPurseProperty {
    /// The service has the value-limited purse option disabled.
    Disabled,
    /// The service has the option enabled. For an overlap service, the
    /// effective limits come from its destination service.
    Enabled {
        /// Upper value reported by the card.
        upper_limit: i32,
        /// Lower value reported by the card.
        lower_limit: i32,
        /// Generation reported by the card for the limit configuration.
        generation: u8,
    },
}

impl ValueLimitedPurseProperty {
    fn parse(record: &[u8; 10]) -> Result<Self, CardError> {
        let &[flag, fields @ ..] = record;
        match flag {
            0 if fields == [0xff; 9] => Ok(Self::Disabled),
            0 => Err(CardError::PursePropertyDisabledFields),
            1 => {
                let [u0, u1, u2, u3, l0, l1, l2, l3, generation] = fields;
                Ok(Self::Enabled {
                    upper_limit: i32::from_le_bytes([u0, u1, u2, u3]),
                    lower_limit: i32::from_le_bytes([l0, l1, l2, l3]),
                    generation,
                })
            }
            other => Err(CardError::PursePropertyFlag(other)),
        }
    }
}

impl<S: Selection> Card<S> {
    /// Request key versions for 1 to 32 nodes in the selected system.
    /// Use `0xffff` to address the system key. A dual-capable card reports
    /// the DES version for a node holding a DES key, otherwise its AES version.
    pub fn request_service(&mut self, nodes: &[u16]) -> Result<Vec<KeyVersion>, Error<S::Error>> {
        let mut parameters = Vec::new();
        append_codes(&mut parameters, nodes, 32).map_err(Error::Request)?;
        admit_packet(self.selection(), 11 + 2 * nodes.len()).map_err(Error::Request)?;
        let body = self.exchange_command(0x02, &parameters, 0x03)?;
        let list = counted_items(&body, nodes.len(), 2, 10).map_err(Error::Response)?;
        Ok(versions(list))
    }

    /// Request algorithm-specific key versions for 1 to 32 nodes.
    /// Cards that omit this command may give no reply.
    pub fn request_service_v2(&mut self, nodes: &[u16]) -> Result<V2KeyVersions, Error<S::Error>> {
        let mut parameters = Vec::new();
        append_codes(&mut parameters, nodes, 32).map_err(Error::Request)?;
        let body = self.exchange_command(0x32, &parameters, 0x33)?;
        let body = success_payload(&body).map_err(Error::Response)?;
        let Some((&identifier, list)) = body.split_first() else {
            return Err(Error::Response(CardError::Length {
                expected: 14,
                actual: body.len() + 12,
            }));
        };
        match identifier {
            0x4f => {
                let list = counted_items(list, nodes.len(), 2, 13).map_err(Error::Response)?;
                Ok(V2KeyVersions::Aes(versions(list)))
            }
            0x41 | 0x43 => {
                let list = counted_items(list, nodes.len(), 4, 13).map_err(Error::Response)?;
                let (aes, des) = list.split_at(nodes.len() * 2);
                Ok(V2KeyVersions::AesAndDes {
                    identifier,
                    aes: versions(aes),
                    des: versions(des),
                })
            }
            other => Err(Error::Response(CardError::CryptoIdentifier(other))),
        }
    }

    /// Query the advertised card OS version and optional feature versions.
    pub fn request_specification_version(
        &mut self,
    ) -> Result<SpecificationVersion, Error<S::Error>> {
        let body = self.exchange_command(0x3c, &[0, 0], 0x3d)?;
        let body = success_payload(&body).map_err(Error::Response)?;
        let [format, lo, hi, count, ..] = body else {
            return Err(Error::Response(CardError::Length {
                expected: 16,
                actual: body.len() + 12,
            }));
        };
        if *format != 0 {
            return Err(Error::Response(CardError::SpecificationFormat(*format)));
        }
        let list =
            counted_items(&body[3..], usize::from(*count), 2, 15).map_err(Error::Response)?;
        Ok(SpecificationVersion {
            basic: u16::from_le_bytes([*lo, *hi]),
            options: words(list).collect(),
        })
    }

    /// Query the SD2 MAC communication enable flag of each requested service.
    /// Takes 1 to 16 service codes and returns flags in request order.
    /// Availability depends on the card.
    pub fn mac_service_properties(
        &mut self,
        services: &[u16],
    ) -> Result<Vec<bool>, Error<S::Error>> {
        self.node_properties(0x01, services, |&[flag]| match flag {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CardError::MacProperty(other)),
        })
    }

    /// Query the value-limited purse property of each requested service.
    /// Takes 1 to 16 service codes and returns properties in request order.
    /// Availability depends on the card.
    pub fn value_limited_purse_properties(
        &mut self,
        services: &[u16],
    ) -> Result<Vec<ValueLimitedPurseProperty>, Error<S::Error>> {
        self.node_properties(0x00, services, ValueLimitedPurseProperty::parse)
    }

    fn node_properties<T, const WIDTH: usize>(
        &mut self,
        selector: u8,
        services: &[u16],
        decode: impl FnMut(&[u8; WIDTH]) -> Result<T, CardError>,
    ) -> Result<Vec<T>, Error<S::Error>> {
        let mut parameters = Vec::from([selector]);
        append_codes(&mut parameters, services, 16).map_err(Error::Request)?;
        // Length, response code, IDm, both status flags, and node count.
        const HEADER_LEN: usize = 13;
        admit_packet(self.selection(), HEADER_LEN + WIDTH * services.len())
            .map_err(Error::Request)?;
        let body = self.exchange_command(0x28, &parameters, 0x29)?;
        let body = success_payload(&body).map_err(Error::Response)?;
        let entries =
            counted_items(body, services.len(), WIDTH, HEADER_LEN - 1).map_err(Error::Response)?;
        entries
            .as_chunks::<WIDTH>()
            .0
            .iter()
            .map(decode)
            .collect::<Result<_, _>>()
            .map_err(Error::Response)
    }

    /// Request Mode0 and check the addressed card's status. An authenticated
    /// session must use its own consuming reset operation.
    pub fn reset_mode(&mut self) -> Result<(), Error<S::Error>> {
        let body = self.exchange_command(0x3e, &[0, 0], 0x3f)?;
        if body.len() != 2 {
            return Err(Error::Response(CardError::Length {
                expected: 12,
                actual: body.len() + 10,
            }));
        }
        success_payload(&body).map_err(Error::Response)?;
        Ok(())
    }
}

fn success_payload(body: &[u8]) -> Result<&[u8], CardError> {
    match body {
        [0, 0, payload @ ..] => Ok(payload),
        [flag1, flag2] => Err(CardError::Status {
            flag1: *flag1,
            flag2: *flag2,
        }),
        _ => Err(CardError::Length {
            expected: 12,
            actual: body.len() + 10,
        }),
    }
}

fn counted_items(
    body: &[u8],
    expected: usize,
    width: usize,
    header: usize,
) -> Result<&[u8], CardError> {
    let Some((&count, list)) = body.split_first() else {
        return Err(CardError::Length {
            expected: header + 1,
            actual: header,
        });
    };
    let actual = usize::from(count);
    if actual != expected {
        return Err(CardError::ResponseCount { expected, actual });
    }
    if list.len() != width * expected {
        return Err(CardError::Length {
            expected: header + 1 + width * expected,
            actual: header + body.len(),
        });
    }
    Ok(list)
}

fn words(list: &[u8]) -> impl Iterator<Item = u16> + '_ {
    list.as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
}

fn versions(list: &[u8]) -> Vec<KeyVersion> {
    words(list).map(KeyVersion).collect()
}
