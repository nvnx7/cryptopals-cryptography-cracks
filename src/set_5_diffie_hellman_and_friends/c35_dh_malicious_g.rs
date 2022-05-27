use crate::utils::aes::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::utils::diffie_hellman::DH;
use crate::utils::sha::sha1_hash;

struct Comms {
    pub dh: DH,
    ack: bool, // acknowledged
}

impl Comms {
    // first actor (A) open a communication channel
    pub fn init(p: &[u8], g: &[u8]) -> (Vec<u8>, Vec<u8>, Self) {
        let dh = DH::new(p, g);
        let comm = Self { dh, ack: false };

        (p.to_vec(), g.to_vec(), comm)
    }

    // second actor (B) acknowledges with received p & g
    pub fn acknowledge(&mut self, p: &[u8], g: &[u8]) -> Result<(), String> {
        if p.iter().eq(self.dh.p.iter()) && g.iter().eq(self.dh.g.iter()) {
            self.ack = true;
            Ok(())
        } else {
            Err("acknowledgement failed!".to_string())
        }
    }

    // Participate generating a public key
    pub fn participate(&mut self, pk: &[u8], iv: &[u8]) -> Vec<u8> {
        if !self.ack {
            panic!("communication not acknowledged yet!");
        }
        let pub_key = self.dh.gen_pub_key(pk);
        pub_key
    }

    pub fn encrypt_msg(&self, msg: &[u8], pk: &[u8], pub_key_other: &[u8], iv: &[u8]) -> Vec<u8> {
        let sk = self.dh.gen_session_key(pub_key_other, pk);
        let key = sha1_hash(&sk).iter().take(16).cloned().collect::<Vec<u8>>();
        aes128_cbc_encrypt(msg, &key, &iv).unwrap()
    }

    pub fn decrypt_msg(
        &self,
        ciphertext: &[u8],
        pk: &[u8],
        pub_key_other: &[u8],
        iv: &[u8],
    ) -> Vec<u8> {
        let sk = self.dh.gen_session_key(pub_key_other, pk);
        let key = sha1_hash(&sk).iter().take(16).cloned().collect::<Vec<u8>>();
        aes128_cbc_decrypt(ciphertext, &key, iv).unwrap()
    }
}

pub fn simulate_crack(
    p: &[u8],
    g: &[u8],
    pk_a: &[u8],
    pk_b: &[u8],
    iv_a: &[u8],
    iv_b: &[u8],
    msg: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // A opens a communication channel f(p, g)
    let (p, g, mut comm) = Comms::init(p, g);

    // B acknowledges with received p & g
    let res = comm.acknowledge(&p, &g);
    assert!(res.is_ok());

    // M intercepts and changes g -> p
    comm.dh.g = comm.dh.p.clone();

    // A participates generating a public key
    let pub_key_a = comm.participate(pk_a, iv_a);

    // B participates generating a public key
    let pub_key_b = comm.participate(pk_b, iv_b);

    // Computed pub_key_a & pub_key_b at this point must be 0. And so does
    // shared secret key, sk. This is because now g = p. Hence,
    // A = (g ** a) % p
    // so, A = (p ** a) % p = 0
    // Therefore, sk = (A ** b) % p
    // or,        sk = (0 ** b) % p = 0
    // where (A = public key, a = private key, sk = shared secret)
    // Same goes for B.
    // Hence M is able to determine encryption key of A and B as:
    let cracked_key = sha1_hash(&[0])
        .iter()
        .take(16)
        .cloned()
        .collect::<Vec<u8>>();

    // A encrypts message and sends ciphertext + A's iv to B
    let cipher_a = comm.encrypt_msg(msg, pk_a, &pub_key_b, iv_a);

    // M is able intercept the A's encrypted message
    let cracked_msg_a = aes128_cbc_decrypt(&cipher_a, &cracked_key, iv_a).unwrap();
    assert_eq!(msg, cracked_msg_a.as_slice());

    // B encrypts message and sends ciphertext + B's iv to A
    let cipher_b = comm.encrypt_msg(msg, pk_b, &pub_key_a, iv_b);

    // M is able intercept the B's encrypted message
    let cracked_msg_b = aes128_cbc_decrypt(&cipher_b, &cracked_key, iv_b).unwrap();

    (cracked_msg_a, cracked_msg_b)
}

#[cfg(test)]
mod test {
    use super::*;

    const P: &[u8] = &[36, 32];
    const G: &[u8] = &[5, 6];

    // random IVs
    const IV_A: &[u8] = b"YELLOW SUBMARINE";
    const IV_B: &[u8] = b"PURPLE SUBMARINE";

    // private keys of A and B
    const PK_A: &[u8] = &[36];
    const PK_B: &[u8] = &[12];

    #[test]
    fn test_c35() {
        let msg = b"hello B!";
        let (cracked_msg_a, cracked_msg_b) = simulate_crack(P, G, PK_A, PK_B, IV_A, IV_B, msg);
        assert_eq!(msg, cracked_msg_a.as_slice());
        assert_eq!(msg, cracked_msg_b.as_slice());
    }
}
