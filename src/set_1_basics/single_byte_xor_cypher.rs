use hex;

// http://en.algoritmy.net/article/40379/Letter-frequency-English
const LETTER_FREQ: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
];

// Chi-Square test (https://en.wikipedia.org/wiki/Chi-squared_test)
fn chi_square(s: &str) -> f64 {
    let mut counts = vec![0_u32; 26];
    let mut n_ignored = 0_u32;

    s.chars().for_each(|c| match c {
        'a'..='z' => {
            counts[c as usize - 97] += 1;
        }
        'A'..='Z' => {
            counts[c as usize - 65] += 1;
        }
        _ => {
            n_ignored += 1;
        }
    });

    let mut score: f64 = 0_f64;
    let length = s.len() as u32 - n_ignored;

    let mut observed: f64;
    let mut expected: f64;
    for i in 0..26 {
        observed = counts[i] as f64;
        expected = (length as f64) * LETTER_FREQ[i];
        score += f64::powf(observed - expected, 2_f64) / expected;
    }

    score
}

pub fn decipher_message(hex: &str) -> String {
    let cipher_bytes = hex::decode(hex).unwrap();
    let mut key_bytes: Vec<u8>;

    let mut message = String::new();
    let mut best_score = f64::MAX;
    for c in 'A'..='Z' {
        key_bytes = vec![c as u8; cipher_bytes.len()];

        let msg_bytes: Vec<u8> = cipher_bytes
            .iter()
            .zip(key_bytes.iter())
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect();

        let msg = std::str::from_utf8(&msg_bytes).unwrap();
        let score = chi_square(msg);

        // Best score is lowest chi-square value
        if score < best_score {
            best_score = score;
            message = String::from(msg);
        }
    }

    message
}

#[cfg(test)]
mod test {
    use super::decipher_message;
    #[test]
    fn decipher() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let message = "Cooking MC's like a pound of bacon";
        assert_eq!(decipher_message(hex), message);
    }
}
