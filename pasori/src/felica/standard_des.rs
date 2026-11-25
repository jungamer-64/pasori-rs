//! FeliCa Standard DES authentication and encrypted block access.
//!
//! The system, area and service keys must belong to the polled system.
//! Supply a new CSPRNG challenge for each authentication.

use super::{
    Card, IssueInformation, StandardError as Error, StandardSession, admit_packet, code_count,
    standard_session::Cipher, validate_packet,
};
use alloc::vec::Vec;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use core::fmt;
use des::{
    Des, TdesEde2,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use felica_packet::Selection;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const HEADER_LEN: usize = 8;
const MAC_LEN: usize = 8;

/// One area in the ordered DES authentication path.
pub struct AreaKey<'a> {
    /// Area code sent to the card.
    pub code: u16,
    /// DES area key.
    pub key: &'a [u8; 8],
}

impl fmt::Debug for AreaKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AreaKey")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

/// An entry in the DES authentication service list and its key contribution.
pub enum ServiceKey<'a> {
    /// A service that contributes a key to the authentication chain.
    Authenticated {
        /// Service code sent to the card.
        code: u16,
        /// DES service key.
        key: &'a [u8; 8],
    },
    /// A service that shares the block list but contributes no key.
    AuthenticationFree(u16),
}

impl fmt::Debug for ServiceKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated { code, .. } => f
                .debug_struct("Authenticated")
                .field("code", code)
                .finish_non_exhaustive(),
            Self::AuthenticationFree(code) => {
                f.debug_tuple("AuthenticationFree").field(code).finish()
            }
        }
    }
}

impl<S: Selection> Card<S> {
    /// Consume this selection and establish a DES session with 1 to 32
    /// ordered areas and 1 to 16 ordered services. Provide the root area
    /// explicitly if it is part of the card's authentication path.
    ///
    /// Authentication-free services occupy their position in the block
    /// address list without contributing a key. Use the card's byte order
    /// for the system key, all area and service keys, and the fresh challenge.
    pub fn authenticate_standard_des(
        mut self,
        system_key: &[u8; 8],
        areas: &[AreaKey<'_>],
        services: &[ServiceKey<'_>],
        challenge: [u8; 8],
    ) -> Result<StandardSession<S>, Error<S::Error>> {
        let area_count = code_count(areas.len(), 32).map_err(Error::Request)?;
        let service_count = code_count(services.len(), 16).map_err(Error::Request)?;
        if !services
            .iter()
            .any(|service| matches!(service, ServiceKey::Authenticated { .. }))
        {
            return Err(Error::NoAuthenticatedService);
        }
        admit_packet(
            self.selection(),
            (20 + 2 * (areas.len() + services.len())).max(34),
        )
        .map_err(Error::Request)?;

        let mut parameters = Vec::with_capacity(10 + 2 * (areas.len() + services.len()));
        let mut group = Zeroizing::new(*system_key);
        parameters.push(area_count);
        for area in areas {
            parameters.extend(area.code.to_le_bytes());
            Des::new(area.key.into()).encrypt_block((&mut *group).into());
        }
        let mut user = Zeroizing::new(*group);
        parameters.push(service_count);
        for service in services {
            let code = match service {
                ServiceKey::Authenticated { code, key } => {
                    Des::new((*key).into()).encrypt_block((&mut *user).into());
                    *code
                }
                ServiceKey::AuthenticationFree(code) => *code,
            };
            parameters.extend(code.to_le_bytes());
        }
        let idm = self.idm();
        for (byte, id_byte) in group.iter_mut().zip(idm.as_bytes()) {
            *byte ^= id_byte;
        }
        let mut alpha = user;
        Des::new((&*group).into()).encrypt_block((&mut *alpha).into());
        let mut beta = Zeroizing::new(*group);
        Des::new((&*alpha).into()).encrypt_block((&mut *beta).into());
        let host_cipher = two_key_cipher(&alpha, &group);
        let card_cipher = two_key_cipher(&group, &beta);

        let challenge = Zeroizing::new(challenge);
        let mut proof = Zeroizing::new(*challenge);
        host_cipher.encrypt_block((&mut *proof).into());
        parameters.extend(*proof);

        self.begin_authentication();
        let reply = self
            .exchange_command(0x10, &parameters, 0x11)
            .map_err(|cause| Error::Exchange {
                command: 0x10,
                cause,
            })?;
        let [card_proof, card_challenge] = reply.as_chunks::<8>().0 else {
            return Err(Error::Layout);
        };
        if reply.len() != 16 {
            return Err(Error::Layout);
        }
        let mut expected = Zeroizing::new(*challenge);
        card_cipher.encrypt_block((&mut *expected).into());
        if !bool::from(expected.ct_eq(card_proof)) {
            return Err(Error::CardProof);
        }

        let mut random = Zeroizing::new(*card_challenge);
        card_cipher.decrypt_block((&mut *random).into());
        let mut host_proof = Zeroizing::new(*random);
        host_cipher.encrypt_block((&mut *host_proof).into());
        let reply = self
            .exchange_addressed(0x12, &*host_proof)
            .map_err(|cause| Error::Exchange {
                command: 0x12,
                cause,
            })?;
        let cipher = DesCipher {
            key: random,
            tid: core::array::from_fn(|index| challenge[index + 2]),
        };
        let (counter, issue) = cipher.open(0x13, reply)?;
        let issue = IssueInformation::parse(&issue)?;
        Ok(StandardSession::new(
            self,
            Cipher::Des(cipher),
            counter,
            issue,
            services.len(),
        ))
    }
}

fn two_key_cipher(first: &[u8; 8], second: &[u8; 8]) -> TdesEde2 {
    let mut key = Zeroizing::new([0; 16]);
    key[..8].copy_from_slice(first);
    key[8..].copy_from_slice(second);
    TdesEde2::new((&*key).into())
}

pub(super) struct DesCipher {
    key: Zeroizing<[u8; 8]>,
    tid: [u8; 6],
}

fn padding_len(payload_len: usize) -> usize {
    8 - payload_len % 8
}

pub(super) fn packet_len(payload_len: usize) -> usize {
    2 + HEADER_LEN + payload_len + padding_len(payload_len) + MAC_LEN
}

impl DesCipher {
    pub(super) fn seal(&self, code: u8, counter: u16, payload: &[u8]) -> Option<Vec<u8>> {
        let length = u8::try_from(packet_len(payload.len())).ok()?;
        let padding = u8::try_from(padding_len(payload.len())).ok()?;
        let mut packet = Zeroizing::new(Vec::with_capacity(usize::from(length)));
        packet.extend([length, code]);
        packet.extend(counter.to_le_bytes());
        packet.extend(self.tid);
        packet.extend_from_slice(payload);
        packet.resize(usize::from(length) - MAC_LEN, padding);
        let mac = packet_mac(length, code, &packet[2..]);
        packet.extend(*mac);
        let plaintext = &mut packet[2..];
        let len = plaintext.len();
        cbc::Encryptor::<Des>::new((&*self.key).into(), (&[0; 8]).into())
            .encrypt_padded::<NoPadding>(plaintext, len)
            .ok()?;
        Some(core::mem::take(&mut *packet))
    }

    fn open<E>(&self, code: u8, packet: Vec<u8>) -> Result<(u16, Zeroizing<Vec<u8>>), Error<E>> {
        validate_packet(&packet, code, 2 + HEADER_LEN + MAC_LEN).map_err(|_| Error::Layout)?;
        let mut packet = Zeroizing::new(packet);
        let length = packet[0];
        let plaintext = cbc::Decryptor::<Des>::new((&*self.key).into(), (&[0; 8]).into())
            .decrypt_padded::<NoPadding>(&mut packet[2..])
            .map_err(|_| Error::Layout)?;
        let (auth, tag) = plaintext.split_at(plaintext.len() - MAC_LEN);
        let expected = packet_mac(length, code, auth);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(Error::Mac);
        }
        let [lo, hi, tid @ ..] = *auth.first_chunk::<HEADER_LEN>().ok_or(Error::Layout)?;
        if tid != self.tid {
            return Err(Error::TransactionId);
        }
        Ok((
            u16::from_le_bytes([lo, hi]),
            Zeroizing::new(auth[HEADER_LEN..].to_vec()),
        ))
    }

    pub(super) fn open_operation<E>(
        &self,
        code: u8,
        packet: Vec<u8>,
        success_len: usize,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Error<E>> {
        let (counter, mut payload) = self.open(code, packet)?;
        let length = if payload.starts_with(&[0, 0]) {
            success_len
        } else {
            2
        };
        // Padding is authenticated. Interpret its length from the command's
        // response layout, without assigning a semantic value to its bytes.
        if payload.len() != length + padding_len(length) {
            return Err(Error::Layout);
        }
        payload.truncate(length);
        Ok((counter, payload))
    }
}

fn packet_mac(length: u8, code: u8, data: &[u8]) -> Zeroizing<[u8; 8]> {
    let mut mac = Zeroizing::new([length, code, 0, 0, 0, 0, 0, 0]);
    for block in data.as_chunks::<8>().0 {
        Des::new(block.into()).encrypt_block((&mut *mac).into());
    }
    mac
}
