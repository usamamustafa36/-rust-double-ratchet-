use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

mod double_ratchet;
use double_ratchet::RatchetState;

fn main() {
    println!("=== Double Ratchet N-Round Communication Demo ===");

    // Number of full Alice↔Bob exchanges
    const N_ROUNDS: usize = 10;

    // Step 1: Secure random initial root (in real life from handshake KDF)
    let mut initial_root = vec![0u8; 32];
    OsRng.fill_bytes(&mut initial_root);
    println!("Initial root (hex): {}", hex::encode(&initial_root));

    // Static X25519 keys (simulating pre-handshake keys / identity + ephemeral)
    let alice_sk = StaticSecret::random_from_rng(&mut OsRng);
    let bob_sk = StaticSecret::random_from_rng(&mut OsRng);

    let alice_pk = PublicKey::from(&alice_sk);
    let bob_pk = PublicKey::from(&bob_sk);

    println!("Alice public key (hex): {}", hex::encode(alice_pk.as_bytes()));
    println!("Bob   public key (hex): {}", hex::encode(bob_pk.as_bytes()));

    // Decide a stable "initiator" role based on static key ordering
    let alice_is_initiator = alice_pk.as_bytes() < bob_pk.as_bytes();
    let bob_is_initiator = !alice_is_initiator;
    println!("Alice is initiator ? {}", alice_is_initiator);
    println!("Bob   is initiator ? {}", bob_is_initiator);

    // Step 2: Create ratchet states with explicit roles
    let mut alice = RatchetState::new(initial_root.clone(), alice_is_initiator);
    let mut bob = RatchetState::new(initial_root.clone(), bob_is_initiator);

    // Step 3: Derive initial shared secret and initialize chains
    let shared_secret = alice_sk.diffie_hellman(&bob_pk);
    let shared_bytes = shared_secret.as_bytes();

    alice.init_chains_from_shared_secret(shared_bytes);
    bob.init_chains_from_shared_secret(shared_bytes);

    println!("Initialized ratchet chains.\n");

    // ============================================================
    // N-ROUND BIDIRECTIONAL COMMUNICATION
    // ============================================================
    for round in 1..=N_ROUNDS {
        println!("================ ROUND {} ================", round);

        // -----------------------
        // Alice → Bob
        // -----------------------
        let alice_msg = format!("Message {} from Alice", round);
        let ct_a = alice
            .encrypt(alice_msg.as_bytes())
            .expect("Alice encrypt failed");

        println!(
            "[Alice → Bob] ciphertext (hex): {}",
            hex::encode(&ct_a)
        );

        let pt_a = bob.decrypt(&ct_a).expect("Bob decrypt failed");
        println!(
            "[Alice → Bob] decrypted: {}",
            String::from_utf8(pt_a).unwrap()
        );

        // -----------------------
        // Bob → Alice
        // -----------------------
        let bob_msg = format!("Reply {} from Bob", round);
        let ct_b = bob
            .encrypt(bob_msg.as_bytes())
            .expect("Bob encrypt failed");

        println!(
            "[Bob → Alice] ciphertext (hex): {}",
            hex::encode(&ct_b)
        );

        let pt_b = alice.decrypt(&ct_b).expect("Alice decrypt failed");
        println!(
            "[Bob → Alice] decrypted: {}",
            String::from_utf8(pt_b).unwrap()
        );

        println!();
    }

    println!("\nDemo complete — {} secure round trips executed.", N_ROUNDS);
}
