use hex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn detect_aes_ecb_encryption(path: &str) -> (usize, usize) {
    let file = File::open(path).expect("Error reading file!");
    let lines = BufReader::new(file).lines();
    let mut i_line: usize = 0;
    let mut max_identical_blocks: usize = 0;

    let mut n_identical_blocks: usize;
    for (i, line) in lines.enumerate() {
        let hex = line.unwrap();
        // Hex line to bytes vec
        let bytes = hex::decode(hex).unwrap();

        // Divide bytes into 16 byte blocks (&[u8] blocks)
        let blocks: Vec<_> = bytes.chunks_exact(16).collect();

        // Get unique blocks
        let unique_blocks: HashSet<_> = blocks.iter().cloned().collect();

        // No. of identical blocks detected
        n_identical_blocks = blocks.len() - unique_blocks.len();

        // Cipher containing most identical blocks is more likely to be
        // ECB mode encrypted
        if n_identical_blocks > max_identical_blocks {
            max_identical_blocks = n_identical_blocks;
            i_line = i;
        }
    }

    (i_line, max_identical_blocks)
}

#[cfg(test)]
mod test {
    use super::detect_aes_ecb_encryption;
    #[test]
    fn test_c8() {
        let (line_no, _) = detect_aes_ecb_encryption("files/set_1/8_hex.txt");
        assert_eq!(line_no, 132);
    }
}
