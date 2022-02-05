use crate::utils::aes::{aes128_ecb_decrypt, aes128_ecb_encrypt};
use std::collections::HashMap;

const UNKNOWN_KEY: &[u8] = b"YELLOW SUBMARINE";

pub fn parse_key_value(inp: &str) -> HashMap<String, String> {
    inp.split('&')
        .map(|kv| kv.split('=').collect::<Vec<_>>())
        .map(|v| (String::from(v[0]), String::from(v[1])))
        .collect()
}

pub fn profile_for(email: &str) -> String {
    if email.chars().any(|c| c == '&' || c == '=') {
        panic!("Metacharacters not allowed!");
    } else {
        format!("email={}&uid=10&role=user", email)
    }
}

pub fn encrypt_user_profile(profile: &str) -> Vec<u8> {
    // let rand_key: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    aes128_ecb_encrypt(profile.as_bytes(), UNKNOWN_KEY).unwrap()
}

pub fn decode_user_profile(cipherbytes: &[u8]) -> HashMap<String, String> {
    let bytes = aes128_ecb_decrypt(cipherbytes, UNKNOWN_KEY).unwrap();
    parse_key_value(&String::from_utf8_lossy(&bytes))
}

// Attacker
pub fn create_admin_profile() -> (Vec<u8>, String) {
    // Chosen email such that last block doesn't contain
    // meta-chars (= and &) in profile
    let chosen_email = "attck@bar.com";

    // Yields "email=attck@bar.com&uid=10&role=user"
    // With plain-text blocks -
    // block 1: email=attck@bar.
    // block 2: com&uid=10&role=
    // block 3: user\x0c\x0c.....(len 16) (with pkcs#7)
    let profile = profile_for(chosen_email);

    // Encrypted blocks corresponding to 3 blocks above. Have to
    // somehow replace last block corresponding to "admin\x0b\x0b..." (len 16)
    let cipherbytes = encrypt_user_profile(&profile);

    // No. of padding required if role was admin in target profile
    // which is "email=attck@bar.com&uid=10&role=admin"
    let target_pad = (16 - "admin".len()) as u8;

    // Target last block required - "admin\x0b\x0b\x0b....." (len 16)
    // instead of "user\x0c\x0c\x0c.....".
    let target_last_block = "admin"
        .chars()
        .chain((0..target_pad).map(|_| target_pad as char))
        .collect::<String>();

    // Email such that one of the blocks in profile contains our
    // target_last_block - 'admin\x0c\x0c\x0c.....';
    let attack_email = format!("attck@bar.{}", target_last_block);

    // Yields "email=attck@bar.admin\x0c\x0c\x0c....&uid=10&role=user"
    // With "admin\x0c\x0c..." as second block whose encryption will be
    // retrieved
    let attack_profile = profile_for(&attack_email);

    let attack_cipherbytes = encrypt_user_profile(&attack_profile);

    // Retrieve second block which corresponds to cipher encryption of
    // target_last_block
    let role_block = attack_cipherbytes
        .iter()
        .skip(16)
        .take(16)
        .cloned()
        .collect::<Vec<u8>>();

    // Encrypted profile corresponding to target profile -
    // "email=attck@bar.com&uid=10&role=admin"
    let target_profile = cipherbytes
        .iter()
        .take(16)
        .chain(cipherbytes.iter().skip(16).take(16))
        .chain(role_block.iter())
        .cloned()
        .collect::<Vec<u8>>();

    (target_profile, chosen_email.to_owned())
}

#[cfg(test)]
mod test {
    use super::{create_admin_profile, decode_user_profile};
    use std::collections::HashMap;
    #[test]
    fn test_c13() {
        let (out, admin_email) = create_admin_profile();
        let profile = decode_user_profile(&out);

        let mut target = HashMap::new();
        target.insert("email".to_owned(), admin_email);
        target.insert("uid".to_owned(), "10".to_owned());
        target.insert("role".to_owned(), "admin".to_owned());
        assert_eq!(profile.get("email"), target.get("email"));
        assert_eq!(profile.get("uid"), target.get("uid"));
        assert_eq!(profile.get("role"), target.get("role"));
    }
}
