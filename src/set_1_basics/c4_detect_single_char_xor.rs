use crate::utils::letter_freq_test::calc_letter_freq_score;
use hex;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn detect_message(path: &str) -> String {
    let mut message = String::new();
    let mut best_score: f64 = f64::MIN;

    let file = File::open(path).expect("Error reading file!");
    let lines = BufReader::new(file).lines();

    let mut line: String;
    let mut key: u16;
    for line_result in lines {
        line = line_result.unwrap();
        for c in 0..255 {
            key = c as u16;

            let msg_bytes: Vec<u16> = hex::decode(&line.trim())
                .unwrap()
                .iter()
                .map(|&b| (b as u16) ^ key)
                .collect();

            let msg = String::from_utf16(&msg_bytes).unwrap();
            let score = calc_letter_freq_score(&msg);

            if score > best_score {
                best_score = score;
                message = String::from(msg);
            }
        }
    }

    message
}

#[cfg(test)]
mod test {
    use super::detect_message;
    #[test]
    fn test_c4() {
        let output = detect_message("files/set_1/4_strings.txt");
        let message = "Now that the party is jumping\n";
        assert_eq!(output, message);
    }
}
