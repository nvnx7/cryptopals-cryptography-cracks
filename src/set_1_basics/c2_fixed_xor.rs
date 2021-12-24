use hex::{decode, encode};

pub fn fixed_xor(hex1: &str, hex2: &str) -> String {
    let bytes1 = decode(hex1).unwrap();
    let bytes2 = decode(hex2).unwrap();

    let xor_bytes: Vec<u8> = bytes1
        .iter()
        .zip(bytes2.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();
    encode(xor_bytes)
}

#[cfg(test)]
mod test {
    use super::fixed_xor;
    #[test]
    fn test_c2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let xor = "746865206b696420646f6e277420706c6179";

        assert_eq!(fixed_xor(hex1, hex2), xor);
    }
}
