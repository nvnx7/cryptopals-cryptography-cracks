pub fn hamming_distance_str(s1: &str, s2: &str) -> u32 {
    s1.chars().zip(s2.chars()).fold(0_u32, |dist, (c1, c2)| {
        let bin1 = format!("{:08b}", c1 as u8);
        let bin2 = format!("{:08b}", c2 as u8);

        dist + bin1
            .chars()
            .zip(bin2.chars())
            .fold(0_u32, |d, (ch1, ch2)| if ch1 == ch2 { d } else { d + 1 })
    })
}

pub fn hamming_distance_bytes(b1: &[u8], b2: &[u8]) -> u32 {
    if b1.len() != b2.len() {
        panic!("Unequal byte slices!");
    }

    b1.iter().zip(b2.iter()).fold(0_u32, |dist, (x1, x2)| {
        let bin1 = format!("{:08b}", x1);
        let bin2 = format!("{:08b}", x2);

        dist + bin1
            .chars()
            .zip(bin2.chars())
            .fold(0_u32, |d, (ch1, ch2)| if ch1 == ch2 { d } else { d + 1 })
    })
}
