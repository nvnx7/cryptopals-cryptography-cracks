use crate::utils::aes::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::utils::bitwise::xor_bytes;

const UNKNOWN_KEY: &[u8] = b"YELLOW SUBMARINE";
const UNKNOWN_IV: &[u8] = b"YELLOW SUBMARINE";

pub fn encrypt_data(data: &str) -> Vec<u8> {
    if data.chars().any(|c| c == ';' || c == '=') {
        panic!("Included prohibited characters!")
    } else {
        let inp = format!(
            "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon",
            data
        );
        aes128_cbc_encrypt(inp.as_bytes(), UNKNOWN_KEY, UNKNOWN_IV)
    }
}

pub fn decrypt_and_find_admin(cipherbytes: &[u8]) -> Option<usize> {
    let msg_bytes = aes128_cbc_decrypt(cipherbytes, UNKNOWN_KEY, UNKNOWN_IV);
    let msg = String::from_utf8_lossy(&msg_bytes);
    msg.find(";admin=true;")
}

pub fn bit_flip_attack(block_size: usize) -> Vec<u8> {
    // Index of target block to flip bits of (assumed prepend text is known )
    let target_block_idx = 1;

    // This should covert to AAAAA;admin=true after attack
    let trojan_plaintext_block = "A".repeat(block_size);

    let mut cipherbytes = encrypt_data(&trojan_plaintext_block);

    let target_cipher_block = cipherbytes
        .iter()
        .skip(target_block_idx * block_size)
        .take(block_size)
        .cloned()
        .collect::<Vec<u8>>();

    // Cipher block just before xor operation during decryption process
    let pre_xor_target_cipher_block =
        xor_bytes(&target_cipher_block, trojan_plaintext_block.as_bytes());

    // Desired plaintext block
    let final_block = "AAAAA;admin=true".as_bytes();

    // Required replacement of target block to produce desired next block
    let replacement = xor_bytes(&pre_xor_target_cipher_block, final_block);

    cipherbytes.splice(
        target_block_idx * block_size..(target_block_idx * block_size) + block_size,
        replacement,
    );

    cipherbytes
}

#[cfg(test)]
mod test {
    use super::{bit_flip_attack, decrypt_and_find_admin, encrypt_data};
    #[test]
    fn test_c16() {
        let cipherbytes = bit_flip_attack(16);
        let idx = decrypt_and_find_admin(&cipherbytes);
        assert!(idx.is_some());
    }
}
