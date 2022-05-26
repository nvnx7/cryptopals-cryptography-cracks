use hex;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const P: &'static str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
const G: u32 = 5;

fn modexp(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    let mut e: BigUint = Zero::zero();
    let mut c: BigUint = One::one();

    while e < *exp {
        e = e + 1_u8;

        c = (base.clone() * c) % m.clone();
    }
    c
}

pub fn gen_pub_key(pk: &BigUint) -> BigUint {
    let g = BigUint::from(G);
    let p_bytes = hex::decode(P).unwrap();
    let p = BigUint::from_bytes_be(&p_bytes);
    modexp(&g, &pk, &p)
}

pub fn gen_session_key(pub_key: &BigUint, pk: &BigUint) -> BigUint {
    let p_bytes = hex::decode(P).unwrap();
    let p = BigUint::from_bytes_be(&p_bytes);
    modexp(&pub_key, &pk, &p)
}

#[allow(non_snake_case)]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_c33() {
        let a = BigUint::from(5u8);
        let b = BigUint::from(4u8);
        let A = gen_pub_key(&a);
        let B = gen_pub_key(&b);
        let sk_A = gen_session_key(&A, &b);
        let sk_B = gen_session_key(&B, &a);

        assert_eq!(sk_A, sk_B);
    }
}
