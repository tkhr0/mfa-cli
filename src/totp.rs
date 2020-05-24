use super::hotp;
use byteorder::{BigEndian, WriteBytesExt};
use std::time::SystemTime;

// Time step
const TIME_STEP: u64 = 30;

// TOTP を計算する
pub fn totp(secret: &[u8]) -> Result<String, String> {
    let current_time = match current_time() {
        Ok(time) => time,
        Err(err) => return Err(err),
    };

    let t = current_time / TIME_STEP;

    let mut byte_t = Vec::new();
    byte_t.write_u64::<BigEndian>(t).unwrap();

    gen_totp(secret, &byte_t)
}

fn gen_totp(secret: &[u8], counter: &[u8]) -> Result<String, String> {
    hotp::hotp(secret, counter)
}

// UNIX time からの経過秒数を返す
fn current_time() -> Result<u64, String> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => Ok(n.as_secs()),
        Err(_) => Err(String::from("SystemTime before UNIX EPOCH!")),
    }
}
