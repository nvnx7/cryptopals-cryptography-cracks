use crate::utils::aes::aes128_ecb_encrypt;
use base64;
use std::collections::HashMap;

const UNKNOWN_KEY: &[u8] = b"YELLOW SUBMARINE";
const UNKNOWN_SECRET: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
const UNKNOWN_PREFIX: &[u8] = b"r4nd0m length of s0m3 r4and0m pr3f1x";

fn unknown_key_encrypt(msg: &[u8]) -> Vec<u8> {
    let append_bytes = base64::decode(UNKNOWN_SECRET).unwrap();
    let buffer: Vec<u8> = UNKNOWN_PREFIX
        .iter()
        .chain(msg.iter())
        .chain(append_bytes.iter())
        .cloned()
        .collect();
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

pub fn detect_prefix_len(block_size: usize) -> usize {
    let mut len: usize = 0;

    let a = 'a' as u8;
    let mut inp = vec![a; block_size * 2];

    // Detect index of ECB repeated blocks to calculate prefix length
    for i in 0..block_size {
        let cipherbytes = unknown_key_encrypt(&inp);
        let blocks = cipherbytes.chunks_exact(block_size).collect::<Vec<&[u8]>>();
        let repeated_block_idx = (0..blocks.len() - 1).find(|i| blocks[*i] == blocks[i + 1]);

        if let Some(idx) = repeated_block_idx {
            len = (idx * block_size) - i;
            break;
        }

        inp.push(a);
    }

    len
}

pub fn decrypt_unknown(block_size: usize, prefix_len: usize) -> String {
    let mut unknown_bytes: Vec<u8> = Vec::new();
    let a = 'A' as u8;

    // No. of extra bytes required to have even blocks
    // containing the prefix
    let n_extra_prefix_bytes = block_size - prefix_len % block_size;

    // No. of starting blocks which contain prefix
    let n_prefix_blocks = f32::ceil((prefix_len as f32) / (block_size as f32)) as usize;

    let mut codebook = HashMap::new();
    let mut i_block = 0;
    loop {
        let input = if i_block == 0 {
            vec![a; block_size - 1 - unknown_bytes.len() + n_extra_prefix_bytes]
        } else {
            std::iter::repeat(&a)
                .take(n_extra_prefix_bytes)
                .chain(
                    unknown_bytes
                        .iter()
                        .rev()
                        .take(block_size - 1 - (unknown_bytes.len() % block_size)),
                )
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
                .skip(i_block * block_size + n_prefix_blocks * block_size)
                .take(block_size)
                .cloned()
                .collect::<Vec<_>>();

            codebook.insert(out_block, n as u8);
        }

        let cipherbytes = unknown_key_encrypt(&input);

        let matched_byte = codebook
            .get(
                &cipherbytes[i_block * block_size + n_prefix_blocks * block_size
                    ..(i_block * block_size + n_prefix_blocks * block_size) + block_size],
            )
            .unwrap();

        unknown_bytes.push(*matched_byte);
        codebook.clear();

        if (i_block * block_size + n_prefix_blocks * block_size) + block_size == cipherbytes.len() {
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
    use super::{
        decrypt_unknown, detect_block_size, detect_prefix_len, UNKNOWN_KEY, UNKNOWN_PREFIX,
    };
    #[test]
    fn test_c14() {
        let block_size = detect_block_size();
        assert_eq!(block_size, UNKNOWN_KEY.len());

        let prefix_len = detect_prefix_len(block_size);
        assert_eq!(prefix_len, UNKNOWN_PREFIX.len());

        let secret = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}";
        let out = decrypt_unknown(block_size, prefix_len);
        assert_eq!(out, secret);
    }
}
