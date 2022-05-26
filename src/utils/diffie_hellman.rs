use num_bigint::BigUint;
use num_traits::{One, Zero};

pub struct DH {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
}

impl DH {
    pub fn new(p: &[u8], g: &[u8]) -> Self {
        Self {
            p: p.to_vec(),
            g: g.to_vec(),
        }
    }

    pub fn gen_pub_key(&self, pk: &[u8]) -> Vec<u8> {
        modexp(&self.g, pk, &self.p)
    }

    pub fn gen_session_key(&self, pub_key: &[u8], pk: &[u8]) -> Vec<u8> {
        modexp(pub_key, pk, &self.p)
    }
}

fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let exp = BigUint::from_bytes_be(exponent);
    let b = BigUint::from_bytes_be(base);
    let m = BigUint::from_bytes_be(modulus);

    let mut e: BigUint = Zero::zero();
    let mut c: BigUint = One::one();

    while e < exp {
        e = e + 1_u8;

        c = (b.clone() * c) % m.clone();
    }
    c.to_bytes_be()
}
