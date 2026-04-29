use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

const KEY_SIZE: usize = 32;

/// Derive new root key + send chain seed + recv chain seed
///
/// Uses HKDF with:
/// - info = "DoubleRatchetRoot"   → new root key
/// - info = "DoubleRatchetSend"   → sending chain seed
/// - info = "DoubleRatchetRecv"   → receiving chain seed
fn kdf_root(
    root_key: &[u8; KEY_SIZE],
    dh_out: &[u8; KEY_SIZE],
) -> ([u8; KEY_SIZE], [u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);

    let mut new_root = [0u8; KEY_SIZE];
    let mut send_ck = [0u8; KEY_SIZE];
    let mut recv_ck = [0u8; KEY_SIZE];

    hk.expand(b"DoubleRatchetRoot", &mut new_root)
        .expect("hkdf expand ok");
    hk.expand(b"DoubleRatchetSend", &mut send_ck)
        .expect("hkdf expand ok");
    hk.expand(b"DoubleRatchetRecv", &mut recv_ck)
        .expect("hkdf expand ok");

    (new_root, send_ck, recv_ck)
}

/// Per-chain KDF (used for both sending and receiving chains).
///
/// Input: current chain key CK
/// Outputs:
/// - msg_key    (info = "DoubleRatchetMessage")
/// - next_ck    (info = "DoubleRatchetChain")
///
/// We also derive (and ignore) a header key with info = "DoubleRatchetHeader"
/// so your header label is still used and separated.
fn kdf_chain(ck: &[u8; KEY_SIZE]) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let hk = Hkdf::<Sha256>::new(None, ck);

    let mut msg_key = [0u8; KEY_SIZE];
    let mut next_ck = [0u8; KEY_SIZE];
    let mut _header_key = [0u8; KEY_SIZE];

    hk.expand(b"DoubleRatchetMessage", &mut msg_key)
        .expect("hkdf expand ok");
    hk.expand(b"DoubleRatchetChain", &mut next_ck)
        .expect("hkdf expand ok");
    hk.expand(b"DoubleRatchetHeader", &mut _header_key)
        .expect("hkdf expand ok");

    (msg_key, next_ck)
}

/// Convert u64 counter to a 96-bit (12-byte) nonce for ChaCha20-Poly1305.
///
/// Layout: [0,0,0,0, counter_le_8_bytes]
fn nonce_from_counter(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from_slice(&n).clone()
}

/// Double Ratchet state (simplified, single DH at start, no further DH ratchets)
#[derive(Clone)]
pub struct RatchetState {
    root_key: [u8; KEY_SIZE],

    // Symmetric chains
    send_chain_key: Option<[u8; KEY_SIZE]>,
    recv_chain_key: Option<[u8; KEY_SIZE]>,

    // Counters for nonce construction
    ns: u64, // messages sent on current sending chain
    nr: u64, // messages received on current receiving chain
    pn: u64, // previous sending chain size (unused in this demo)

    // Global role: whether this side is "initiator" for mapping send/recv chains
    is_initiator: bool,
}

impl RatchetState {
    /// Create a new ratchet state with a given root seed and role.
    ///
    /// `root` should be at least 32 bytes; we take the first 32 as root key.
    /// `is_initiator` must be **true on exactly one side**, false on the other.
    pub fn new(root: Vec<u8>, is_initiator: bool) -> Self {
        let mut root_key = [0u8; KEY_SIZE];
        if root.len() >= KEY_SIZE {
            root_key.copy_from_slice(&root[0..KEY_SIZE]);
        } else {
            // If shorter, stretch with HKDF
            let hk = Hkdf::<Sha256>::new(None, &root);
            hk.expand(b"DoubleRatchetRoot", &mut root_key)
                .expect("hkdf expand ok");
        }

        Self {
            root_key,
            send_chain_key: None,
            recv_chain_key: None,
            ns: 0,
            nr: 0,
            pn: 0,
            is_initiator,
        }
    }

    /// Initialize send/recv chains from the precomputed shared secret (DH output).
    ///
    /// Uses:
    ///   RK', CK_s, CK_r = HKDF(RK, secret)
    /// And then:
    ///   - initiator: send = CK_s, recv = CK_r
    ///   - responder: send = CK_r, recv = CK_s
    pub fn init_chains_from_shared_secret(&mut self, secret: &[u8]) {
        let mut ss = [0u8; KEY_SIZE];
        if secret.len() >= KEY_SIZE {
            ss.copy_from_slice(&secret[0..KEY_SIZE]);
        } else {
            let hk = Hkdf::<Sha256>::new(None, secret);
            hk.expand(b"init-shared", &mut ss)
                .expect("hkdf expand ok");
        }

        let (new_root, send_ck_seed, recv_ck_seed) = kdf_root(&self.root_key, &ss);
        self.root_key = new_root;

        if self.is_initiator {
            // This side is "initiator": send = send_ck_seed, recv = recv_ck_seed
            self.send_chain_key = Some(send_ck_seed);
            self.recv_chain_key = Some(recv_ck_seed);
        } else {
            // This side is "responder": send = recv_ck_seed, recv = send_ck_seed
            self.send_chain_key = Some(recv_ck_seed);
            self.recv_chain_key = Some(send_ck_seed);
        }

        self.ns = 0;
        self.nr = 0;
        self.pn = 0;
    }

    /// Encrypt a plaintext message with the current sending chain.
    ///
    /// Derivations:
    ///   - msg_key, next_ck = kdf_chain(CK_s)
    ///   - nonce = nonce_from_counter(ns)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ck = self
            .send_chain_key
            .ok_or_else(|| anyhow!("send_chain_key not initialized"))?;

        let (msg_key, next_ck) = kdf_chain(&ck);
        self.send_chain_key = Some(next_ck);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce = nonce_from_counter(self.ns);

        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| anyhow!(e.to_string()))?;

        self.ns = self.ns.wrapping_add(1);
        Ok(ct)
    }

    /// Decrypt a ciphertext message with the current receiving chain.
    ///
    /// Derivations:
    ///   - msg_key, next_ck = kdf_chain(CK_r)
    ///   - nonce = nonce_from_counter(nr)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ck = self
            .recv_chain_key
            .ok_or_else(|| anyhow!("recv_chain_key not initialized"))?;

        let (msg_key, next_ck) = kdf_chain(&ck);
        self.recv_chain_key = Some(next_ck);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let nonce = nonce_from_counter(self.nr);

        let pt = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|e| anyhow!(e.to_string()))?;

        self.nr = self.nr.wrapping_add(1);
        Ok(pt)
    }
}
