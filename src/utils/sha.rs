use sha1::{Digest, Sha1};

pub fn sha1_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.iter().map(|x| *x).collect()
}
