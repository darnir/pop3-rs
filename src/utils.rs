extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::md5::Md5;

pub fn get_apop_digest(timestamp: &str, password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.input_str(timestamp);
    hasher.input_str(password);
    hasher.result_str()
}
