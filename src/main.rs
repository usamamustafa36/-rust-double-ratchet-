use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

mod double_ratchet;
use double_ratchet::RatchetState;

const N_ROUNDS: usize = 10;

fn main() -> anyhow::Result<()> {
    println!("=== Double Ratchet N-round demo ===");

    // In a real session this secret comes from a handshake such as Noise XX.
    let mut shared_secret = [0u8; 32];
    OsRng.fill_bytes(&mut shared_secret);

    let bob_keypair = StaticSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_keypair);

    let mut alice = RatchetState::init_initiator(&shared_secret, bob_public);
    let mut bob = RatchetState::init_responder(&shared_secret, bob_keypair);

    for round in 1..=N_ROUNDS {
        println!("--- round {round} ---");

        let wire = alice.encrypt(format!("Message {round} from Alice").as_bytes(), b"")?;
        println!("Alice ratchet key: {}", hex::encode(alice.public_key().as_bytes()));
        println!("Alice -> Bob: {}", String::from_utf8(bob.decrypt(&wire, b"")?)?);

        let wire = bob.encrypt(format!("Reply {round} from Bob").as_bytes(), b"")?;
        println!("Bob ratchet key:   {}", hex::encode(bob.public_key().as_bytes()));
        println!("Bob -> Alice: {}", String::from_utf8(alice.decrypt(&wire, b"")?)?);
    }

    println!("{N_ROUNDS} round trips completed.");
    Ok(())
}
