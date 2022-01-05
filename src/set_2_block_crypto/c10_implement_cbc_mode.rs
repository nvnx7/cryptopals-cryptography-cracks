use crate::set_2_block_crypto::c9_implement_pkcs_padding::pad_pkcs7;
use crate::utils::bitwise::xor_bytes;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::Aes128;

pub fn aes_128_cbc_encrypt(message: &str, key_str: &str, iv_str: &str) -> String {
    // Normalize message by pkcs7 padding
    let padded_message = pad_pkcs7(message, 16);
    let msg_bytes = padded_message.as_bytes();
    let iv = iv_str.as_bytes().to_vec();

    let key = GenericArray::clone_from_slice(key_str.as_bytes());
    let cipher = Aes128::new(&key);

    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();
    (0..message.len()).step_by(16).for_each(|x| {
        // Take last encrypted block or IV for first block iteration
        let last = encrypted_blocks.last().unwrap_or(&iv);

        // XOR last encrypted block with current msg block & encrypt result
        let xor_block = xor_bytes(last, &msg_bytes[x..x + 16]);
        let mut block = GenericArray::clone_from_slice(&xor_block);
        cipher.encrypt_block(&mut block);

        encrypted_blocks.push(block.into_iter().collect::<Vec<u8>>());
    });

    hex::encode(encrypted_blocks.into_iter().flatten().collect::<Vec<u8>>())
}

pub fn aes_128_cbc_decrypt(cipher_hex: &str, key_str: &str, iv_str: &str) -> String {
    let encrypted_bytes = hex::decode(cipher_hex).unwrap();
    let key = GenericArray::clone_from_slice(key_str.as_bytes());
    let iv = iv_str.as_bytes();
    let cipher = Aes128::new(&key);

    let mut decrypted_blocks: Vec<Vec<u8>> = Vec::new();
    (0..encrypted_bytes.len()).step_by(16).for_each(|x| {
        // Take last of encrypted block or IV in case of first block iteration
        let last = if x == 0 {
            &iv
        } else {
            &encrypted_bytes[x - 16..x]
        };

        // Decrypt AES
        let mut block = GenericArray::clone_from_slice(&encrypted_bytes[x..x + 16]);
        cipher.decrypt_block(&mut block);
        let decrypted_block = block.into_iter().collect::<Vec<u8>>();

        // XOR decrypted block with last encrypted block to undo xor during encryption
        let xor_block = xor_bytes(last, &decrypted_block);
        decrypted_blocks.push(xor_block);
    });

    // Get number of padding bytes applied during encryption & remove padding
    let padding_byte = *decrypted_blocks.last().unwrap().last().unwrap() as usize;
    decrypted_blocks
        .into_iter()
        .flatten()
        .take(encrypted_bytes.len() - padding_byte)
        .map(|x| x as char)
        .collect::<String>()
}

#[cfg(test)]
mod test {
    use super::{aes_128_cbc_decrypt, aes_128_cbc_encrypt};
    #[test]
    fn test_c10() {
        let msg = "This is some secret message. Do not reveal. I mean really this is some secret..duh! Why would you want to reveal it anyway.";
        let key = "YELLOW SUBMARINE";
        let iv = "\x00".repeat(16);

        let encrypted_msg_hex = aes_128_cbc_encrypt(msg, key, iv.as_str());
        let decrypted_msg = aes_128_cbc_decrypt(encrypted_msg_hex.as_str(), key, iv.as_str());
        assert_eq!(msg, decrypted_msg);
    }
}
