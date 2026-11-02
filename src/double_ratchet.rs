//! Signal-style Double Ratchet over X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
//!
//! Two ratchets:
//!   * DH ratchet    — a fresh X25519 keypair each time the conversation changes
//!                     direction, mixed into the root key. Provides post-compromise
//!                     security: an attacker holding stolen state is locked out as
//!                     soon as the peer replies with a public key they never saw.
//!   * Chain ratchet — one HKDF step per message, producing a single-use message
//!                     key. Provides forward secrecy: superseded keys are wiped and
//!                     cannot be recomputed.
//!
//! Wire format: `header (48 bytes) || ChaCha20-Poly1305 ciphertext`.
//! The header is authenticated as AAD, so `dh_pub`, `pn`, and `n` cannot be
//! tampered with without the tag failing.
//!
//! Cargo.toml:
//!   anyhow = "1"
//!   hkdf = "0.12"
//!   sha2 = "0.10"
//!   chacha20poly1305 = "0.10"
//!   x25519-dalek = { version = "2", features = ["static_secrets"] }
//!   rand_core = { version = "0.6", features = ["getrandom"] }
//!   zeroize = "1"

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const HEADER_SIZE: usize = 48;

/// Cap on how many message keys we will derive and stash for a single gap.
/// Without this, a forged header claiming `n = u64::MAX` is a denial of service.
const MAX_SKIP: u64 = 1000;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Root step. Salt is the chaining value, IKM is the fresh DH output — the
/// raw X25519 shared secret is not uniformly distributed, so it belongs in the
/// extract input, not the salt.
///
/// `RK', CK = HKDF(salt = RK, ikm = dh_out, info = "DoubleRatchetRoot")`
fn kdf_root(root_key: &[u8; KEY_SIZE], dh_out: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);

    let mut okm = [0u8; KEY_SIZE * 2];
    hk.expand(b"DoubleRatchetRoot", &mut okm)
        .expect("hkdf expand: output length is within 255*HashLen");

    let mut new_root = [0u8; KEY_SIZE];
    let mut chain_key = [0u8; KEY_SIZE];
    new_root.copy_from_slice(&okm[..KEY_SIZE]);
    chain_key.copy_from_slice(&okm[KEY_SIZE..]);
    okm.zeroize();

    (new_root, chain_key)
}

/// Chain step. Input is already a uniform 32-byte key, so no salt is needed.
///
/// `MK, CK' = HKDF(ikm = CK, info = "DoubleRatchetChain")`
fn kdf_chain(ck: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let hk = Hkdf::<Sha256>::new(None, ck);

    let mut okm = [0u8; KEY_SIZE * 2];
    hk.expand(b"DoubleRatchetChain", &mut okm)
        .expect("hkdf expand: output length is within 255*HashLen");

    let mut msg_key = [0u8; KEY_SIZE];
    let mut next_ck = [0u8; KEY_SIZE];
    msg_key.copy_from_slice(&okm[..KEY_SIZE]);
    next_ck.copy_from_slice(&okm[KEY_SIZE..]);
    okm.zeroize();

    (msg_key, next_ck)
}

/// Split a message key into an AEAD key and nonce. Every message key is unique,
/// so the nonce derived from it is never reused under the same key.
fn message_keys(msg_key: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let hk = Hkdf::<Sha256>::new(None, msg_key);

    let mut okm = [0u8; KEY_SIZE + NONCE_SIZE];
    hk.expand(b"DoubleRatchetMessage", &mut okm)
        .expect("hkdf expand: output length is within 255*HashLen");

    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    key.copy_from_slice(&okm[..KEY_SIZE]);
    nonce.copy_from_slice(&okm[KEY_SIZE..]);
    okm.zeroize();

    (key, nonce)
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// Travels in the clear but is authenticated as AAD.
///
/// * `dh`  — sender's current ratchet public key. A value the receiver has not
///           seen before is what triggers a DH ratchet step.
/// * `pn`  — number of messages sent on the sender's *previous* chain, so the
///           receiver knows how many keys to stash before ratcheting.
/// * `n`   — index of this message within the current chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: [u8; KEY_SIZE],
    pub pn: u64,
    pub n: u64,
}

impl Header {
    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[..KEY_SIZE].copy_from_slice(&self.dh);
        out[KEY_SIZE..KEY_SIZE + 8].copy_from_slice(&self.pn.to_be_bytes());
        out[KEY_SIZE + 8..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            bail!("message too short to contain a header");
        }
        let mut dh = [0u8; KEY_SIZE];
        dh.copy_from_slice(&bytes[..KEY_SIZE]);

        let mut pn_bytes = [0u8; 8];
        pn_bytes.copy_from_slice(&bytes[KEY_SIZE..KEY_SIZE + 8]);
        let mut n_bytes = [0u8; 8];
        n_bytes.copy_from_slice(&bytes[KEY_SIZE + 8..HEADER_SIZE]);

        Ok(Header {
            dh,
            pn: u64::from_be_bytes(pn_bytes),
            n: u64::from_be_bytes(n_bytes),
        })
    }
}

// ---------------------------------------------------------------------------
// Ratchet state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RatchetState {
    /// Our current ratchet keypair. Replaced on every DH ratchet step.
    dhs: StaticSecret,
    /// Peer's latest ratchet public key. `None` until we hear from them.
    dhr: Option<PublicKey>,

    root_key: [u8; KEY_SIZE],
    send_chain_key: Option<[u8; KEY_SIZE]>,
    recv_chain_key: Option<[u8; KEY_SIZE]>,

    /// Messages sent on the current sending chain.
    ns: u64,
    /// Messages received on the current receiving chain.
    nr: u64,
    /// Messages sent on the previous sending chain.
    pn: u64,

    /// Keys for messages that arrived out of order or not at all, indexed by
    /// (ratchet public key, message number).
    skipped: HashMap<([u8; KEY_SIZE], u64), [u8; KEY_SIZE]>,
}

impl RatchetState {
    /// The side that speaks first. Needs the peer's ratchet public key up front,
    /// which the handshake (X3DH, Noise XX, etc.) is responsible for supplying.
    pub fn init_initiator(shared_secret: &[u8; KEY_SIZE], their_public: PublicKey) -> Self {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dh_out = dhs.diffie_hellman(&their_public);
        let (root_key, send_ck) = kdf_root(shared_secret, dh_out.as_bytes());

        Self {
            dhs,
            dhr: Some(their_public),
            root_key,
            send_chain_key: Some(send_ck),
            recv_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// The side that listens first. Holds the keypair whose public half the
    /// initiator already has; its sending chain opens on the first message received.
    pub fn init_responder(shared_secret: &[u8; KEY_SIZE], our_keypair: StaticSecret) -> Self {
        Self {
            dhs: our_keypair,
            dhr: None,
            root_key: *shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.dhs)
    }

    /// Advance the chain ratchet once and encrypt. Cheap and local — no
    /// interaction with the peer, so any number of messages can be sent in a row.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ck = self
            .send_chain_key
            .ok_or_else(|| anyhow!("no sending chain: waiting for the peer's first message"))?;

        let (mut msg_key, next_ck) = kdf_chain(&ck);
        let header = Header {
            dh: self.public_key().to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        let header_bytes = header.to_bytes();

        let mut associated = Vec::with_capacity(HEADER_SIZE + aad.len());
        associated.extend_from_slice(&header_bytes);
        associated.extend_from_slice(aad);

        let (mut key, nonce) = message_keys(&msg_key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated,
                },
            )
            .map_err(|e| anyhow!("aead encrypt failed: {e}"))?;

        key.zeroize();
        msg_key.zeroize();

        // Only now is the old chain key superseded.
        let mut old = self.send_chain_key.take().expect("checked above");
        old.zeroize();
        self.send_chain_key = Some(next_ck);
        self.ns += 1;

        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt. All state changes happen on a scratch copy and are committed only
    /// after the AEAD tag verifies, so a forged or corrupted packet cannot
    /// desynchronise the session.
    pub fn decrypt(&mut self, message: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let header = Header::from_bytes(message)?;
        let (header_bytes, ciphertext) = message.split_at(HEADER_SIZE);

        let mut associated = Vec::with_capacity(HEADER_SIZE + aad.len());
        associated.extend_from_slice(header_bytes);
        associated.extend_from_slice(aad);

        // A key stashed earlier for a message that arrived late.
        if let Some(mut msg_key) = self.skipped.get(&(header.dh, header.n)).copied() {
            let plaintext = decrypt_with(&msg_key, ciphertext, &associated);
            msg_key.zeroize();
            if let Ok(pt) = plaintext {
                if let Some(mut k) = self.skipped.remove(&(header.dh, header.n)) {
                    k.zeroize();
                }
                return Ok(pt);
            }
            bail!("authentication failed for a skipped message");
        }

        let mut trial = self.clone();

        // An unseen ratchet key means the conversation has changed direction.
        if trial.dhr.map(|k| k.to_bytes()) != Some(header.dh) {
            trial.skip_message_keys(header.pn)?;
            trial.dh_ratchet(&header);
        }
        trial.skip_message_keys(header.n)?;

        let ck = trial
            .recv_chain_key
            .ok_or_else(|| anyhow!("no receiving chain"))?;
        let (mut msg_key, next_ck) = kdf_chain(&ck);

        let plaintext = decrypt_with(&msg_key, ciphertext, &associated);
        msg_key.zeroize();
        let plaintext = plaintext?;

        trial.recv_chain_key = Some(next_ck);
        trial.nr += 1;
        *self = trial;

        Ok(plaintext)
    }

    /// Derive and stash keys for messages `nr..until` that we have not seen.
    fn skip_message_keys(&mut self, until: u64) -> Result<()> {
        if self.recv_chain_key.is_none() {
            return Ok(());
        }
        if until > self.nr && until - self.nr > MAX_SKIP {
            bail!("header claims {} skipped messages, over the limit", until - self.nr);
        }

        let dhr = match self.dhr {
            Some(k) => k.to_bytes(),
            None => return Ok(()),
        };

        while self.nr < until {
            let ck = self.recv_chain_key.expect("checked above");
            let (msg_key, next_ck) = kdf_chain(&ck);
            self.skipped.insert((dhr, self.nr), msg_key);
            let mut old = self.recv_chain_key.take().expect("checked above");
            old.zeroize();
            self.recv_chain_key = Some(next_ck);
            self.nr += 1;
        }
        Ok(())
    }

    /// The purple column. Two root steps: one to open the receiving chain against
    /// the peer's new key, one to open a fresh sending chain against a brand-new
    /// keypair of our own. The second is what evicts an attacker holding old state.
    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;

        let their_public = PublicKey::from(header.dh);
        self.dhr = Some(their_public);

        let dh_recv = self.dhs.diffie_hellman(&their_public);
        let (root_key, recv_ck) = kdf_root(&self.root_key, dh_recv.as_bytes());
        self.root_key.zeroize();
        self.root_key = root_key;
        if let Some(mut old) = self.recv_chain_key.take() {
            old.zeroize();
        }
        self.recv_chain_key = Some(recv_ck);

        self.dhs = StaticSecret::random_from_rng(OsRng);
        let dh_send = self.dhs.diffie_hellman(&their_public);
        let (root_key, send_ck) = kdf_root(&self.root_key, dh_send.as_bytes());
        self.root_key.zeroize();
        self.root_key = root_key;
        if let Some(mut old) = self.send_chain_key.take() {
            old.zeroize();
        }
        self.send_chain_key = Some(send_ck);
    }
}

fn decrypt_with(msg_key: &[u8; KEY_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (mut key, nonce) = message_keys(msg_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let result = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("aead authentication failed"));
    key.zeroize();
    result
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(mut k) = self.send_chain_key.take() {
            k.zeroize();
        }
        if let Some(mut k) = self.recv_chain_key.take() {
            k.zeroize();
        }
        for k in self.skipped.values_mut() {
            k.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (RatchetState, RatchetState) {
        let shared = [7u8; KEY_SIZE];
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        (
            RatchetState::init_initiator(&shared, bob_public),
            RatchetState::init_responder(&shared, bob_secret),
        )
    }

    #[test]
    fn in_order_round_trip() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"hello", b"").unwrap();
        assert_eq!(bob.decrypt(&ct, b"").unwrap(), b"hello");
        let ct = bob.encrypt(b"hi back", b"").unwrap();
        assert_eq!(alice.decrypt(&ct, b"").unwrap(), b"hi back");
    }

    #[test]
    fn many_messages_one_direction() {
        let (mut alice, mut bob) = pair();
        for i in 0..8u8 {
            let ct = alice.encrypt(&[i], b"").unwrap();
            assert_eq!(bob.decrypt(&ct, b"").unwrap(), vec![i]);
        }
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = pair();
        let c1 = alice.encrypt(b"one", b"").unwrap();
        let c2 = alice.encrypt(b"two", b"").unwrap();
        let c3 = alice.encrypt(b"three", b"").unwrap();
        assert_eq!(bob.decrypt(&c3, b"").unwrap(), b"three");
        assert_eq!(bob.decrypt(&c1, b"").unwrap(), b"one");
        assert_eq!(bob.decrypt(&c2, b"").unwrap(), b"two");
    }

    #[test]
    fn dh_ratchet_advances_on_direction_change() {
        let (mut alice, mut bob) = pair();
        let first = alice.public_key().to_bytes();
        let ct = alice.encrypt(b"a", b"").unwrap();
        bob.decrypt(&ct, b"").unwrap();
        let ct = bob.encrypt(b"b", b"").unwrap();
        alice.decrypt(&ct, b"").unwrap();
        let ct = alice.encrypt(b"c", b"").unwrap();
        bob.decrypt(&ct, b"").unwrap();
        assert_ne!(alice.public_key().to_bytes(), first);
    }

    #[test]
    fn skipped_across_a_ratchet_step() {
        let (mut alice, mut bob) = pair();
        let c1 = alice.encrypt(b"one", b"").unwrap();
        let _lost = alice.encrypt(b"lost", b"").unwrap();
        bob.decrypt(&c1, b"").unwrap();
        let reply = bob.encrypt(b"reply", b"").unwrap();
        alice.decrypt(&reply, b"").unwrap();
        let c3 = alice.encrypt(b"after", b"").unwrap();
        assert_eq!(bob.decrypt(&c3, b"").unwrap(), b"after");
    }

    #[test]
    fn tampered_ciphertext_is_rejected_and_state_survives() {
        let (mut alice, mut bob) = pair();
        let mut ct = alice.encrypt(b"first", b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(bob.decrypt(&ct, b"").is_err());

        ct[last] ^= 0x01;
        assert_eq!(bob.decrypt(&ct, b"").unwrap(), b"first");
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = pair();
        let mut ct = alice.encrypt(b"first", b"").unwrap();
        ct[KEY_SIZE + 15] ^= 0x01;
        assert!(bob.decrypt(&ct, b"").is_err());
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"first", b"context-a").unwrap();
        assert!(bob.decrypt(&ct, b"context-b").is_err());
    }

    #[test]
    fn absurd_skip_count_is_refused() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"one", b"").unwrap();
        bob.decrypt(&ct, b"").unwrap();

        let mut forged = alice.encrypt(b"two", b"").unwrap();
        forged[KEY_SIZE + 8..HEADER_SIZE].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(bob.decrypt(&forged, b"").is_err());
    }
}
