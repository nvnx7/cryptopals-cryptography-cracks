use crate::utils::hamming_distance::hamming_distance_bytes;
use crate::utils::letter_freq_test::calc_letter_freq_score;
use base64;
use std::fs;

fn read_bytes(path: &str) -> Vec<u8> {
    let base64_s = fs::read_to_string(path)
        .and_then(|res| Ok(res.replace("\n", "")))
        .expect("Error reading file");
    base64::decode(base64_s).unwrap()
}

fn calc_avg_edit_dist(key_sz: usize, txt_bytes: &[u8]) -> f64 {
    let len = txt_bytes.len();
    let mut i: usize = 0;
    let mut dist_sum = 0;
    let mut block1;
    let mut block2;

    loop {
        if i * 2 * key_sz >= len {
            break;
        }

        block1 = &txt_bytes[i * key_sz..(i + 1) * key_sz];
        block2 = &txt_bytes[(i + 1) * key_sz..(i + 2) * key_sz];

        dist_sum += hamming_distance_bytes(block1, block2) / (key_sz as u32);

        i += 1;
    }

    (dist_sum as f64) / (i as f64 + 1.0)
}

fn break_single_char_xor(xor_bytes: &[u8]) -> u8 {
    let mut key: u8 = 0;
    let mut best_score = f64::MIN;
    for key_byte in 0..255 {
        let msg_bytes: Vec<u8> = xor_bytes.iter().map(|&b| b ^ key_byte).collect();

        let msg = String::from_utf8_lossy(&msg_bytes);
        let score = calc_letter_freq_score(&msg);

        if score > best_score {
            best_score = score;
            key = key_byte;
        }
    }

    key
}

pub fn break_repeating_key_xor(path: &str) -> String {
    let text_bytes = read_bytes(path);

    // (key size, edit dist) tuples vec
    let mut edit_dist: Vec<(usize, f64)> = Vec::new();

    for key_sz in 2..=40 {
        let dist = calc_avg_edit_dist(key_sz, &text_bytes);
        edit_dist.push((key_sz, dist));
    }

    // Extract the shortest distance key
    edit_dist.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap());
    let key_sz = edit_dist.pop().and_then(|x| Some(x.0)).unwrap();

    // Key bytes
    let mut key_bytes: Vec<u8> = Vec::new();

    let mut idx;
    let mut ith_bytes: Vec<u8> = Vec::new();
    for i in 0..key_sz {
        // Take ith byte of every block of key_sz len
        idx = i;
        ith_bytes.clear();
        while idx < text_bytes.len() {
            ith_bytes.push(text_bytes[idx]);
            idx += key_sz;
        }

        let key_i = break_single_char_xor(&ith_bytes);
        key_bytes.push(key_i);
    }

    let key: String = key_bytes.iter().map(|&b| b as char).collect();

    key
}

#[cfg(test)]
mod test {
    use super::break_repeating_key_xor;
    #[test]
    fn test_c6() {
        let output = break_repeating_key_xor("files/set_1/6_base64.txt");
        let key = "Terminator X: Bring the noise";
        assert_eq!(output, key);
    }
}
