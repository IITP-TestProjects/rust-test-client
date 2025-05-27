use rand::rngs::OsRng; // rand 0.7 기준
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use crate::vrfs;

/// Generate ed25519 keypair
pub fn generate_keys() -> (PublicKey, SecretKey) {
    let mut csprng = OsRng;
    let keypair: Keypair = Keypair::generate(&mut csprng);
    (keypair.public, keypair.secret)
}

/// VRF Prove and Verify wrappers
pub fn generate_vrf_output(
    seed: &str,
    pubkey: &PublicKey,
    seckey: &SecretKey,
) -> Vec<u8> {
    let msg= Sha256::digest(seed.as_bytes());
    let (pi, _hash) = vrfs::prove(pubkey.as_bytes(), seckey.as_bytes(), &msg);
    let ok = vrfs::verify(pubkey.as_bytes(), &pi, &msg);
    assert!(ok, "VRF verification failed");
    pi
}