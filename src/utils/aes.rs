use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc, Ecb};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

pub fn aes128_ecb_encrypt(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128Ecb::new_from_slices(&key, &[0; 16]).unwrap();
    let pos = msg.len();
    let mut buffer = vec![0u8; pos + 16];
    buffer[..pos].copy_from_slice(msg);
    cipher.encrypt(&mut buffer, msg.len()).unwrap().to_vec()
}

pub fn aes128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128Ecb::new_from_slices(&key, &[0; 16]).unwrap();
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt(&mut buffer).unwrap().to_vec()
}

pub fn aes128_cbc_encrypt(msg: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let pos = msg.len();
    let mut buffer = vec![0u8; pos + 16];
    buffer[..pos].copy_from_slice(msg);
    cipher.encrypt(&mut buffer, pos).unwrap().to_vec()
}

pub fn aes128_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt(&mut buffer).unwrap().to_vec()
}
