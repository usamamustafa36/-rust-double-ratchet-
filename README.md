# Rust Double Ratchet — N-Round Communication Demo

**Author:** Usama Mustafa
**Domain:** Applied cryptography · End-to-end messaging · Signal protocol
**Stack:** Rust · X25519 · ChaCha20-Poly1305 · HKDF-SHA256 · HMAC-SHA256

A from-scratch Rust implementation of the Double Ratchet algorithm — the symmetric ratchet from Signal's end-to-end-encrypted messaging — with a runnable N-round Alice ↔ Bob communication demo.

---

## What is Double Ratchet

The Double Ratchet is the symmetric portion of Signal's E2EE protocol. It combines:
- A **DH ratchet** that re-derives a shared secret on every message round trip
- A **symmetric-key chain** that derives unique forward-secret keys for each individual message

The result: every message has its own key, future messages stay secret if past keys leak (forward secrecy), and past messages stay secret if future keys leak (post-compromise / break-in recovery).

## What's implemented

- X25519 static + ephemeral keys via `x25519-dalek`
- HKDF-SHA256 root-key derivation via `hkdf` + `sha2`
- HMAC-SHA256 chain-key derivation via `hmac`
- ChaCha20-Poly1305 authenticated encryption via `chacha20poly1305`
- N-round Alice ↔ Bob exchange showing rotating root, send chain, and receive chain
- Stable role assignment via static-key ordering
- Hex-encoded key + ciphertext printing for verification

## Run

```bash
cargo run
```

Output shows each round's:
- Updated root key (after DH ratchet)
- Send / receive chain keys (after symmetric ratchet)
- Plaintext, ciphertext, and successful decryption

```
=== Double Ratchet N-Round Communication Demo ===
Initial root (hex): ...
Alice public key (hex): ...
Bob   public key (hex): ...

--- Round 1 ---
Alice → Bob: "Hello Bob, round 1"
Ciphertext (hex): ...
Bob decrypted: "Hello Bob, round 1"
...
```

## Layout

- `src/main.rs` — driver + N-round protocol loop
- `src/double_ratchet.rs` — `RatchetState` struct, DH-ratchet, KDF chains, encrypt / decrypt
- `Cargo.toml` — crate dependencies

## Why this exists

Signal-style ratcheting is widely cited but rarely implemented from scratch. This repo is a teaching / reference implementation showing every state transition of the protocol in clear Rust — useful as a baseline for adding PQC (e.g., replacing X25519 with Kyber in a hybrid handshake), formal verification experiments, or embedded-system ports.

## Future direction

- Replace X25519 with **CRYSTALS-Kyber** (ML-KEM) for a PQC-hardened ratchet
- Add **out-of-order / skipped-message handling** (full Signal-spec compatibility)
- Add **header encryption** layer

## License

MIT
