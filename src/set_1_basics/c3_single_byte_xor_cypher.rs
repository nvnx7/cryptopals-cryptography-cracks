use crate::utils::letter_freq_test::calc_letter_freq_score;

pub fn decipher_message(hex: &str) -> (String, f64) {
    let cipher_bytes = hex::decode(hex).unwrap();
    let mut key_byte: u8;

    let mut message = String::new();
    let mut best_score = f64::MIN;
    for c in 0..=255 {
        key_byte = c as u8;

        let msg_bytes: Vec<u8> = cipher_bytes.iter().map(|&b| b ^ key_byte).collect();

        let msg = String::from_utf8_lossy(&msg_bytes);
        let score = calc_letter_freq_score(&msg);

        if score > best_score {
            best_score = score;
            message = String::from(msg);
        }
    }

    (message, best_score)
}

#[cfg(test)]
mod test {
    use super::decipher_message;
    #[test]
    fn test_c3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let message = "Cooking MC's like a pound of bacon";
        let (output, _) = decipher_message(hex);
        assert_eq!(output, message);
    }
}
