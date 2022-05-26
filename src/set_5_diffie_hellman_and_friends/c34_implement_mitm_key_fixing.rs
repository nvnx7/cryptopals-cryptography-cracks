use crate::utils::aes::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::utils::diffie_hellman::DH;
use crate::utils::sha::sha1_hash;

struct Comms {
    pub dh: DH,
    pub pub_key_a: Vec<u8>,
    pub pub_key_b: Vec<u8>,
    iv_a: Vec<u8>,
    iv_b: Vec<u8>,
}

impl Comms {
    // first actor (A) open a communication channel
    pub fn new(p: &[u8], g: &[u8], pub_key_a: &[u8], iv_a: &[u8]) -> Self {
        Self {
            dh: DH::new(p, g),
            pub_key_a: pub_key_a.to_vec(),
            pub_key_b: Vec::new(),
            iv_a: iv_a.to_vec(),
            iv_b: Vec::new(),
        }
    }

    // second actor (B) choses to initiate the communication
    pub fn init_session(&mut self, pk_b: &[u8], iv_b: &[u8]) {
        let pub_key_b = self.dh.gen_pub_key(pk_b);
        self.pub_key_b = pub_key_b;
        self.iv_b = iv_b.to_vec();
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
    let dh = DH::new(p, g);

    let pub_key_a = dh.gen_pub_key(pk_a);

    // A opens a communication channel f(p, g, A)
    let mut comm = Comms::new(p, g, &pub_key_a, iv_a);

    // M intercepts and changes pub_key_a -> p
    comm.pub_key_a = comm.dh.p.clone();

    // B joins using its private key and iv
    comm.init_session(pk_b, iv_b);

    // Computed shared secret key (comm.sk) at this point must be 0.
    // This is because the shared secret key is computed using the expression:
    // sk = (A ** b) % p. Now since A is changed to p, the shared secret key is:
    // sk = (p ** b) % p = 0.
    // Hence M is able to determine encryption key of A and B as:
    let cracked_key = sha1_hash(&[0])
        .iter()
        .take(16)
        .cloned()
        .collect::<Vec<u8>>();

    // M intercepts again and changes pub_key_b -> p
    // (so that if A computes sk, it will be 0 again)
    comm.pub_key_b = comm.dh.p.clone();

    // A encrypts message and sends ciphertext + A's iv to B
    let cipher_a = comm.encrypt_msg(msg, pk_a, &comm.pub_key_b, &comm.iv_a);

    // M is able intercept the A's encrypted message
    let cracked_msg_a = aes128_cbc_decrypt(&cipher_a, &cracked_key, &comm.iv_a).unwrap();

    // B is able to decrypt the message
    let msg_received = comm.decrypt_msg(&cipher_a, pk_b, &comm.pub_key_a, &comm.iv_a);

    // B encrypts the same message and sends to A
    let cipher_b = comm.encrypt_msg(&msg_received, pk_b, &comm.pub_key_a, &comm.iv_b);

    // M is also able intercept the B's encrypted message
    let cracked_msg_b = aes128_cbc_decrypt(&cipher_b, &cracked_key, &comm.iv_b).unwrap();

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
    fn test_comm() {
        let dh = DH::new(P, G);

        // A opens a communication channel
        let pub_key_a = dh.gen_pub_key(PK_A);
        let mut comm = Comms::new(P, G, &pub_key_a, IV_A);

        // B accepts and initiates
        comm.init_session(PK_B, IV_B);

        // A encrypts message and sends ciphertext + A's iv to B
        let msg = b"hello B!";
        let cipher_a = comm.encrypt_msg(msg, PK_A, &comm.pub_key_b, &comm.iv_a);

        // B is able to decrypt the message
        let msg_received = comm.decrypt_msg(&cipher_a, PK_B, &comm.pub_key_a, &comm.iv_a);
        // To prove legitimacy B encrypts the message again with its own iv
        // and sends the ciphertext + B's iv to A
        let cipher_b = comm.encrypt_msg(&msg_received, PK_B, &comm.pub_key_a, &comm.iv_b);

        // To confirm authenticity A is able to decrypt the same message
        let msg_confirm = comm.decrypt_msg(&cipher_b, PK_A, &comm.pub_key_b, &comm.iv_b);
        assert_eq!(msg, msg_confirm.as_slice());
    }

    #[test]
    fn test_c34() {
        let msg = b"hello B!";
        let (cracked_msg_a, cracked_msg_b) = simulate_crack(P, G, PK_A, PK_B, IV_A, IV_B, msg);
        assert_eq!(msg, cracked_msg_a.as_slice());
        assert_eq!(msg, cracked_msg_b.as_slice());
    }
}
