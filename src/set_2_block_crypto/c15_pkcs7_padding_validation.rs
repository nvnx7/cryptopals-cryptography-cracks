pub fn validate_pkcs7_padding(inp: &str) -> bool {
    let padding_byte = inp.chars().last().unwrap() as u8;
    inp.chars()
        .rev()
        .take(padding_byte as usize)
        .all(|x| x == padding_byte as char)
}

#[cfg(test)]
mod test {
    use super::validate_pkcs7_padding;
    #[test]
    fn test_c15() {
        assert!(validate_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04"));
        assert!(!validate_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05"));
        assert!(!validate_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04"));
    }
}
