use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use num_bigint::BigUint;
use num_traits::Num;
use rand::RngCore;

const LIMIT: usize = 100;
const QS: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
const N2: usize = 32;
const N: usize = 16;
const COFACTOR: u8 = 8;

lazy_static::lazy_static! {
    static ref Q: BigUint = BigUint::from_str_radix(QS, 16).unwrap();
}

/// Generate VRF proof (pi) and output hash
pub fn prove(pk: &[u8], sk: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);

    let x = expand_secret(sk);
    let h = hash_to_curve(m, pk);
    let gamma = &h * &x;
    let k = Scalar::from_bytes_mod_order(bytes);
    let gk = &ED25519_BASEPOINT_POINT * &k;
    let hk = &h * &k;
    let c = hash_points(&[
        ED25519_BASEPOINT_POINT.compress().as_bytes(),
        h.compress().as_bytes(),
        &pk,
        gamma.compress().as_bytes(),
        gk.compress().as_bytes(),
        hk.compress().as_bytes(),
    ]);

    let s = k - c * x;
    let mut pi = Vec::new();
    pi.extend_from_slice(gamma.compress().as_bytes());
    pi.extend_from_slice(&pad_bytes(&c.to_bytes(), N));
    pi.extend_from_slice(&pad_bytes(&s.to_bytes(), N2));
    let hash = hash_output(&pi);
    (pi, hash)
}

/// Verify VRF proof correctness
pub fn verify(pk: &[u8], pi: &[u8], m: &[u8]) -> bool {
    let (gamma, c, s) = decode_proof(pi);
    let P = CompressedEdwardsY(pk.try_into().unwrap()).decompress().unwrap();
    let u = P * &c + ED25519_BASEPOINT_POINT * &s;
    let h = hash_to_curve(m, pk);
    let v = gamma * &c + h * &s;
    let c2 = hash_points(&[
        ED25519_BASEPOINT_POINT.compress().as_bytes(),
        h.compress().as_bytes(),
        &pk,
        gamma.compress().as_bytes(),
        u.compress().as_bytes(),
        v.compress().as_bytes(),
    ]);
    c2 == c
}

fn decode_proof(pi: &[u8]) -> (EdwardsPoint, Scalar, Scalar) {
    let gamma = CompressedEdwardsY(pi[0..N2].try_into().unwrap()).decompress().unwrap();
    let c = Scalar::from_bytes_mod_order(BigUint::from_bytes_be(&pi[N2..N2+N]).to_bytes_be().try_into().unwrap());
    let s = Scalar::from_bytes_mod_order(BigUint::from_bytes_be(&pi[N2+N..N2+N+N2]).to_bytes_be().try_into().unwrap());
    (gamma, c, s)
}

fn pad_bytes(src: &[u8], len: usize) -> Vec<u8> {
    if src.len() >= len {
        src[(src.len()-len)..].to_vec()
    } else {
        vec![0u8; len - src.len()].into_iter().chain(src.iter().copied()).collect()
    }
}

fn expand_secret(sk: &[u8]) -> Scalar {
    let hash = Sha512::digest(&sk[..32]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hash[..32]);
    Scalar::from_bytes_mod_order(buf) // 또는 from_canonical_bytes(buf).unwrap()
}

fn hash_points(points: &[&[u8]]) -> Scalar {
    let mut h = Sha256::new();
    for p in points { h.update(p); }
    let digest = h.finalize();
    let num = BigUint::from_bytes_be(&digest[..N]);
    let c = num % Q.clone();
    let mut buf = [0u8; 32];
    let bytes = c.to_bytes_be();
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(buf)
}

fn hash_to_curve(m: &[u8], pk: &[u8]) -> EdwardsPoint {
    let mut hash = Sha256::new();
    for ctr in 0..LIMIT {
        hash.update(m);
        hash.update(pk);
        hash.update(&(ctr as u32).to_be_bytes());
        let digest = hash.finalize_reset();
        if let Some(p) = CompressedEdwardsY(digest.try_into().unwrap()).decompress() {
            return multiply_cofactor(p);
        }
    }
    panic!("hash_to_curve failed");
}

fn multiply_cofactor(p: EdwardsPoint) -> EdwardsPoint {
    let mut r = p;
    for _ in 1..COFACTOR {
        r = r + p;
    }
    r
}

fn hash_output(pi: &[u8]) -> Vec<u8> {
    pi[1..(N2+1)].to_vec()
}