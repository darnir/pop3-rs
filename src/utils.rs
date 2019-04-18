use md5::{Digest, Md5};

pub fn get_apop_digest(timestamp: &str, password: &str) -> String {
    let hasher = Md5::new().chain(timestamp).chain(password);
    format!("{:x}", hasher.result())
}
