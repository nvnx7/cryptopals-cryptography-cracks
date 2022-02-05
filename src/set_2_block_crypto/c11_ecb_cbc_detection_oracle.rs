use crate::utils::aes::{aes128_cbc_encrypt, aes128_ecb_encrypt};
use rand::Rng;
use std::collections::HashSet;

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

fn gen_rand_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn random_encryption(msg: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let use_ecb: bool = rand::random();
    let rand_key = gen_rand_bytes(16);
    let rand_iv = gen_rand_bytes(16);

    let n_prepend = rand::thread_rng().gen_range(0..11);
    let prepend_bytes = gen_rand_bytes(n_prepend);
    let n_append = rand::thread_rng().gen_range(0..11);
    let append_bytes = gen_rand_bytes(n_append);

    let msg_bytes: Vec<u8> = prepend_bytes
        .iter()
        .chain(msg.iter())
        .chain(append_bytes.iter())
        .cloned()
        .collect();

    let mode: EncryptionMode;
    let cipherbytes;
    if use_ecb {
        mode = EncryptionMode::ECB;
        cipherbytes = aes128_ecb_encrypt(&msg_bytes, &rand_key).unwrap();
    } else {
        cipherbytes = aes128_cbc_encrypt(&msg_bytes, &rand_key, &rand_iv).unwrap();
        mode = EncryptionMode::CBC;
    }

    (cipherbytes, mode)
}

// Returns (predicted_mode, actual_mode)
pub fn detect_mode() -> (EncryptionMode, EncryptionMode) {
    let msg = "z".repeat(64);

    let (cipherbytes, actual_mode) = random_encryption(msg.as_bytes());
    let blocks: Vec<_> = cipherbytes.chunks_exact(16).collect();
    let unique_blocks: HashSet<_> = blocks.iter().cloned().collect();

    // No. of identical blocks detected
    let n_identical_blocks = blocks.len() - unique_blocks.len();
    if n_identical_blocks > 0 {
        (EncryptionMode::ECB, actual_mode)
    } else {
        (EncryptionMode::CBC, actual_mode)
    }
}

#[cfg(test)]
mod test {
    use super::detect_mode;
    #[test]
    fn test_c11() {
        for _ in 0..100 {
            let (predicted_mode, actual_mode) = detect_mode();
            assert_eq!(predicted_mode, actual_mode);
        }
    }
}
