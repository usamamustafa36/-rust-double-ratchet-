# Rust Double Ratchet

**Author:** Usama Mustafa
**Domain:** Applied cryptography · End-to-end messaging · Signal protocol
**Stack:** Rust · X25519 · ChaCha20-Poly1305 · HKDF-SHA256

A Rust implementation of the Double Ratchet algorithm from Signal's end-to-end encrypted messaging, with a runnable N-round Alice ↔ Bob demo.

---

## What is Double Ratchet

The Double Ratchet is the message-encryption layer of the Signal protocol. It combines two ratchets:
- A **DH ratchet** that mixes a fresh X25519 output into the root key each time the conversation changes direction
- A **symmetric-key chain** that derives a new key for every message

Every message gets its own key. Old messages stay secret if current keys leak (forward secrecy), and the session recovers its secrecy after a compromise once new DH values are exchanged (post-compromise security).

## What's implemented

- DH ratchet on each direction change, with X25519 via `x25519-dalek`
- Root and chain key derivation with HKDF-SHA256
- ChaCha20-Poly1305 encryption, with the 48-byte header authenticated as associated data
- Out-of-order delivery through stored skipped keys, capped at 1,000 per gap
- Forged messages leave the session state unchanged, because decryption runs on a scratch copy
- Superseded chain keys are zeroized
- Tests for all of the above: `cargo test`

Header encryption is not implemented, so header fields are authenticated but readable on the wire.

## Run

```bash
cargo run
```

The demo runs ten round trips and prints each side's current ratchet public key, which changes as the DH ratchet advances.

Tests:

```bash
cargo test
```

## Layout

- `src/main.rs` — driver + N-round protocol loop
- `src/double_ratchet.rs` — `RatchetState`, DH ratchet, KDF chains, encrypt / decrypt, tests
- `Cargo.toml` — crate dependencies

## Why this exists

Signal-style ratcheting is widely cited but rarely implemented from scratch. This repo is a teaching / reference implementation showing every state transition of the protocol in clear Rust — useful as a baseline for adding PQC (e.g., replacing X25519 with Kyber in a hybrid handshake), formal verification experiments, or embedded-system ports.

## Future direction

- Replace X25519 with **ML-KEM** for a post-quantum ratchet
- Add a **header encryption** layer

## License

MIT
