use base64;
use hex;

pub fn convert_hex_to_base64(hex: &str) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

#[cfg(test)]
mod test {
    use super::convert_hex_to_base64;
    #[test]
    fn test_c1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(convert_hex_to_base64(hex), base64);
    }
}
