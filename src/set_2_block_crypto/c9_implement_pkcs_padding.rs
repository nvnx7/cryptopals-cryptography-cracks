pub fn pad_pkcs7(message: &str, block_size: usize) -> String {
    let padding_size = block_size - message.len() % block_size;
    let padding_char = padding_size as u8 as char;
    let padding: String = (0..padding_size).map(|_| padding_char).collect();
    format!("{}{}", message, padding)
}

#[cfg(test)]
mod test {
    use super::pad_pkcs7;
    #[test]
    fn test_c9() {
        let output1 = pad_pkcs7("YELLOW SUBMARINE", 20);
        let padded1 = "YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(output1, padded1);

        let output2 = pad_pkcs7("YELLOW SUBMARINEYELLOW SUBMARINE", 16);
        let padded2 = format!(
            "{}{}",
            "YELLOW SUBMARINEYELLOW SUBMARINE",
            "\x10".repeat(16)
        );
        assert_eq!(output2, padded2);
    }
}
