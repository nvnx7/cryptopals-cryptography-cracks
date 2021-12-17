use hex;

pub fn repeated_key_xor(message: &str, key: &str) -> String {
    let key_seq: String = key.chars().cycle().take(message.len()).collect::<String>();

    let key_bytes = key_seq.as_bytes();
    let msg_bytes = message.as_bytes();

    let xor_bytes: Vec<u8> = msg_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();

    hex::encode(xor_bytes)
}

#[cfg(test)]
mod test {
    use super::repeated_key_xor;
    #[test]
    fn repeated_xor() {
        let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let repeated_key = "ICE";

        let output = repeated_key_xor(message, repeated_key);
        let xor_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(output, xor_hex);
    }
}
