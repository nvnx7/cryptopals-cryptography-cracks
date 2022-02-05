use crate::utils::aes::aes128_ecb_encrypt;
use base64;
use std::collections::HashMap;

const UNKNOWN_KEY: &[u8] = b"YELLOW SUBMARINE";
const UNKNOWN_SECRET: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn unknown_key_encrypt(msg: &[u8]) -> Vec<u8> {
    let append_bytes = base64::decode(UNKNOWN_SECRET).unwrap();
    let buffer: Vec<u8> = msg.iter().chain(append_bytes.iter()).cloned().collect();
    aes128_ecb_encrypt(&buffer, UNKNOWN_KEY).unwrap()
}

pub fn detect_block_size() -> usize {
    let block_size;
    let a = 'A' as u8;

    let mut inp = vec![a];
    let last_len = unknown_key_encrypt(&[a; 1]).len();

    loop {
        inp.push(a);
        let cipherbytes = unknown_key_encrypt(&inp);
        if cipherbytes.len() != last_len {
            block_size = cipherbytes.len() - last_len;
            break;
        }
    }

    block_size
}

pub fn decrypt_unknown(block_size: usize) -> String {
    let mut unknown_bytes: Vec<u8> = Vec::new();
    let a = 'A' as u8;

    let mut codebook = HashMap::new();
    let mut i_block = 0;
    loop {
        let input = if i_block == 0 {
            vec![a; block_size - 1 - unknown_bytes.len()]
        } else {
            unknown_bytes
                .iter()
                .rev()
                .take(block_size - 1 - (unknown_bytes.len() % block_size))
                .cloned()
                .collect()
        };

        // Construct code-book map
        for n in 0..255 {
            let byte_short_inp: Vec<u8> = input
                .iter()
                .chain(unknown_bytes.iter())
                .chain(std::iter::once(&n))
                .cloned()
                .collect();

            let out_block = unknown_key_encrypt(&byte_short_inp)
                .iter()
                .skip(i_block * block_size)
                .take(block_size)
                .cloned()
                .collect::<Vec<_>>();
            codebook.insert(out_block, n as u8);
        }
        let cipherbytes = unknown_key_encrypt(&input);

        let matched_byte = codebook
            .get(&cipherbytes[i_block * block_size..(i_block * block_size) + block_size])
            .unwrap();
        unknown_bytes.push(*matched_byte);
        codebook.clear();

        if (i_block * block_size) + block_size == cipherbytes.len() {
            break;
        }

        if unknown_bytes.len() % block_size == 0 {
            i_block += 1;
        }
    }

    String::from_utf8_lossy(&unknown_bytes).to_string()
}

#[cfg(test)]
mod test {
    use super::{decrypt_unknown, detect_block_size};
    #[test]
    fn test_c12() {
        let block_size = detect_block_size();
        assert_eq!(block_size, 16);
        let out = decrypt_unknown(block_size);
        let secret = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}";
        assert_eq!(out, secret);
    }
}
