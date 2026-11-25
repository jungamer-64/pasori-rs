//! FeliCa Standard AES-128 authentication and encrypted block access.
//!
//! The selected card, ordered node keys, and individualization code must
//! belong to the same system. A new CSPRNG challenge is required for every
//! authentication. After sending a command the session can advance only
//! from an authenticated response with a strictly newer transaction number.

use super::{
    Card, IssueInformation, StandardError as Error, StandardSession, admit_packet, code_count,
    standard_session::Cipher,
};
use aes::{
    Aes128,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
};
use alloc::{boxed::Box, vec::Vec};
use cmac::{Cmac, Mac};
use core::fmt;
use felica_packet::Selection;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SECURE_OVERHEAD: usize = 12;

/// An entry in the authentication node list, paired with its AES key.
pub struct NodeKey<'a> {
    /// Card node code.
    pub code: u16,
    /// AES-128 node key.
    pub key: &'a [u8; 16],
}

impl fmt::Debug for NodeKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKey")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl<S: Selection> Card<S> {
    /// Consume the ordinary card selection and authenticate using AES-128.
    /// The ordered node list also defines the indices used by the encrypted
    /// block commands. Supply the system's individualization code, its
    /// operation parameter, and a fresh 16-byte CSPRNG challenge.
    pub fn authenticate_standard_aes(
        mut self,
        nodes: &[NodeKey<'_>],
        individualization: &[u8; 16],
        operation_parameter: u8,
        challenge: [u8; 16],
    ) -> Result<StandardSession<S>, Error<S::Error>> {
        let node_count = code_count(nodes.len(), 16).map_err(Error::Request)?;
        admit_packet(self.selection(), (28 + 2 * nodes.len()).max(46)).map_err(Error::Request)?;
        let mut group = Zeroizing::new([0; 16]);
        group[..2].copy_from_slice(&[1, 1]);
        group[15] = 0x80;
        for node in nodes {
            Aes128::new(node.key.into()).encrypt_block((&mut *group).into());
        }
        xor(&mut group[..], individualization);
        let derivation = Aes128::new((&*group).into());
        let mut context = [0; 16];
        context[1] = 2;
        context[6..14].copy_from_slice(self.selection().poll_response().idm.as_bytes());
        context[14] = 1;
        let alpha = Zeroizing::new(derive(&derivation, context, 1));
        let mut beta = Zeroizing::new(derive(&derivation, context, 2));
        let alpha = Aes128::new((&*alpha).into());

        let challenge = Zeroizing::new(challenge);
        let mut proof = Zeroizing::new(*challenge);
        alpha.encrypt_block((&mut *proof).into());
        let mut parameters = Vec::with_capacity(18 + 2 * nodes.len());
        parameters.extend([operation_parameter, node_count]);
        for node in nodes {
            parameters.extend(node.code.to_le_bytes());
        }
        parameters.extend(*proof);
        self.begin_authentication();
        let first = self
            .exchange_command(0x40, &parameters, 0x41)
            .map_err(|cause| Error::Exchange {
                command: 0x40,
                cause,
            })?;
        let Some((proof, tail)) = first.split_first_chunk::<16>() else {
            return Err(Error::Layout);
        };
        let Some((encrypted_random, context_bytes)) = tail.split_first_chunk::<16>() else {
            return Err(Error::Layout);
        };
        let [salt, a, b, c] = context_bytes else {
            return Err(Error::Layout);
        };
        xor(&mut beta[..4], &[*salt, *a, *b, *c]);
        let beta = Aes128::new((&*beta).into());
        let mut expected = Zeroizing::new(*challenge);
        beta.encrypt_block((&mut *expected).into());
        if !bool::from(expected.ct_eq(proof)) {
            return Err(Error::CardProof);
        }
        let mut random = Zeroizing::new(*encrypted_random);
        beta.decrypt_block((&mut *random).into());
        let mut host_proof = Zeroizing::new(*random);
        alpha.encrypt_block((&mut *host_proof).into());
        let mut key_block = [0; 16];
        key_block[1] = 3;
        key_block[14] = 1;
        let derivation = Aes128::new((&*random).into());
        let encryption = Zeroizing::new(derive(&derivation, key_block, 1));
        let authentication = Zeroizing::new(derive(&derivation, key_block, 2));
        let cipher = Box::new(AesCipher {
            encryption: Aes128::new((&*encryption).into()),
            authentication,
            identifier: core::array::from_fn(|index| challenge[index + 2]),
            salt: [*a, *b, *c],
        });
        let reply = self
            .exchange_addressed(0x42, &*host_proof)
            .map_err(|cause| Error::Exchange {
                command: 0x42,
                cause,
            })?;
        let (counter, issue) = cipher.open(0x43, reply)?;
        let issue = IssueInformation::parse(&issue)?;
        Ok(StandardSession::new(
            self,
            Cipher::Aes(cipher),
            counter,
            issue,
            nodes.len(),
        ))
    }
}

pub(super) fn packet_len(payload_len: usize) -> usize {
    SECURE_OVERHEAD + payload_len
}

pub(super) struct AesCipher {
    encryption: Aes128,
    authentication: Zeroizing<[u8; 16]>,
    identifier: [u8; 6],
    salt: [u8; 3],
}

impl AesCipher {
    fn iv(&self, length: u8, code: u8, counter: [u8; 2]) -> [u8; 16] {
        let mut iv = [0; 16];
        iv[..5].copy_from_slice(&[1, length, code, counter[0], counter[1]]);
        iv[5..11].copy_from_slice(&self.identifier);
        iv[11..14].copy_from_slice(&self.salt);
        iv
    }

    /// Encrypt and authenticate a payload; `None` if it exceeds one packet.
    pub(super) fn seal(&self, code: u8, counter: u16, payload: &mut [u8]) -> Option<Vec<u8>> {
        let length = u8::try_from(packet_len(payload.len())).ok()?;
        let counter = counter.to_le_bytes();
        let iv = self.iv(length, code, counter);
        let mut mac = self.mac(iv, payload)?;
        self.crypt(iv, payload, &mut mac);
        let mut packet = Vec::with_capacity(usize::from(length));
        packet.extend([length, code, counter[0], counter[1]]);
        packet.extend_from_slice(payload);
        packet.extend(mac);
        Some(packet)
    }

    pub(super) fn open<E>(
        &self,
        code: u8,
        packet: Vec<u8>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Error<E>> {
        let [length, response_code, low, high, tail @ ..] = packet.as_slice() else {
            return Err(Error::Layout);
        };
        if *response_code != code || usize::from(*length) != packet.len() || tail.len() < 8 {
            return Err(Error::Layout);
        }
        let mut plaintext = Zeroizing::new(tail.to_vec());
        let payload_len = plaintext.len() - 8;
        let (payload, mac) = plaintext.split_at_mut(payload_len);
        let iv = self.iv(*length, code, [*low, *high]);
        self.crypt(iv, payload, mac);
        if !bool::from(self.mac(iv, payload).ok_or(Error::Layout)?.ct_eq(mac)) {
            return Err(Error::Mac);
        }
        plaintext.truncate(payload_len);
        Ok((u16::from_le_bytes([*low, *high]), plaintext))
    }

    fn crypt(&self, iv: [u8; 16], payload: &mut [u8], mac: &mut [u8]) {
        // The FeliCa OFB stream starts the tag on its own block boundary.
        let mut stream = Zeroizing::new(iv);
        for part in payload.chunks_mut(16).chain(core::iter::once(mac)) {
            self.encryption.encrypt_block((&mut *stream).into());
            xor(part, &*stream);
        }
    }

    /// CMAC over the header and payload; `None` if the length field overflows.
    fn mac(&self, mut header: [u8; 16], payload: &[u8]) -> Option<[u8; 8]> {
        header[0] = 0x19;
        header[14..].copy_from_slice(&u16::try_from(payload.len()).ok()?.to_be_bytes());
        let mut mac = <Cmac<Aes128> as cmac::KeyInit>::new((&*self.authentication).into());
        mac.update(&header);
        mac.update(payload);
        let tag = mac.finalize().into_bytes();
        Some(core::array::from_fn(|index| tag[index]))
    }
}

fn derive(cipher: &Aes128, mut block: [u8; 16], prefix: u8) -> [u8; 16] {
    block[0] = prefix;
    cipher.encrypt_block((&mut block).into());
    block
}

fn xor(data: &mut [u8], mask: &[u8]) {
    for (byte, mask) in data.iter_mut().zip(mask) {
        *byte ^= mask;
    }
}
