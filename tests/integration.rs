use ml_kem_rs::{ml_kem_1024, ml_kem_512, ml_kem_768};

#[test]
fn test_expected_flow_512() {
    // Alice runs KeyGen, and serializes ek for Bob (to bytes)
    let (alice_ek, alice_dk) = ml_kem_512::key_gen();
    let alice_ek_bytes = alice_ek.to_bytes();

    // Alice sends ek bytes to Bob
    let bob_ek_bytes = alice_ek_bytes;

    // Bob deserializes ek bytes, runs Encaps, to get ssk and serializes ct for Alice (to bytes)
    let bob_ek = ml_kem_512::new_ek(bob_ek_bytes);
    let (bob_ssk_bytes, bob_ct) = bob_ek.encaps();
    let bob_ct_bytes = bob_ct.to_bytes();

    // Bob sends ct bytes to Alice
    let alice_ct_bytes = bob_ct_bytes;

    // Alice deserializes runs Decaps
    let alice_ct = ml_kem_512::new_ct(alice_ct_bytes);
    let alice_ssk_bytes = alice_dk.decaps(&alice_ct);

    // Each party obtains the same shared secret key
    assert_eq!(bob_ssk_bytes, alice_ssk_bytes)
}

#[test]
fn test_expected_flow_768() {
    // Alice runs KeyGen, and serializes ek for Bob (to bytes)
    let (alice_ek, alice_dk) = ml_kem_768::key_gen();
    let alice_ek_bytes = alice_ek.to_bytes();

    // Alice sends ek bytes to Bob
    let bob_ek_bytes = alice_ek_bytes;

    // Bob deserializes ek bytes, runs Encaps, to get ssk and serializes ct for Alice (to bytes)
    let bob_ek = ml_kem_768::new_ek(bob_ek_bytes);
    let (bob_ssk_bytes, bob_ct) = bob_ek.encaps();
    let bob_ct_bytes = bob_ct.to_bytes();

    // Bob sends ct bytes to Alice
    let alice_ct_bytes = bob_ct_bytes;

    // Alice deserializes runs Decaps
    let alice_ct = ml_kem_768::new_ct(alice_ct_bytes);
    let alice_ssk_bytes = alice_dk.decaps(&alice_ct);

    // ne for now since values are fixed deltas
    assert_eq!(bob_ssk_bytes, alice_ssk_bytes)
}

#[test]
fn test_expected_flow_1024() {
    // Alice runs KeyGen, and serializes ek for Bob (to bytes)
    let (alice_ek, alice_dk) = ml_kem_1024::key_gen();
    let alice_ek_bytes = alice_ek.to_bytes();

    // Alice sends ek bytes to Bob
    let bob_ek_bytes = alice_ek_bytes;

    // Bob deserializes ek bytes, runs Encaps, to get ssk and serializes ct for Alice (to bytes)
    let bob_ek = ml_kem_1024::new_ek(bob_ek_bytes);
    let (bob_ssk_bytes, bob_ct) = bob_ek.encaps();
    let bob_ct_bytes = bob_ct.to_bytes();

    // Bob sends ct bytes to Alice
    let alice_ct_bytes = bob_ct_bytes;

    // Alice deserializes runs Decaps
    let alice_ct = ml_kem_1024::new_ct(alice_ct_bytes);
    let alice_ssk_bytes = alice_dk.decaps(&alice_ct);

    // ne for now since values are fixed deltas
    assert_eq!(bob_ssk_bytes, alice_ssk_bytes)
}
