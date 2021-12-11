use base64::encode;
use std::num::ParseIntError;

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}

pub fn convert_hex_to_base64(hex: &str) -> String {
    match hex_to_bytes(hex) {
        Ok(bytes) => encode(bytes),
        _ => panic!("Error, check input"),
    }
}

#[cfg(test)]
mod test {
    use super::convert_hex_to_base64;
    #[test]
    fn convert() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(convert_hex_to_base64(hex), base64);
    }
}
