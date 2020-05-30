use super::hotp;
use byteorder::{BigEndian, WriteBytesExt};
use std::time::SystemTime;

// Time step
const TIME_STEP: u64 = 30;

// TOTP を現在時刻から計算する
pub fn totp(secret: &[u8]) -> Result<String, String> {
    match current_time() {
        Ok(current_time) => gen_totp(secret, current_time),
        Err(err) => return Err(err),
    }
}

// TOTP を任意の時刻で計算する
fn gen_totp(secret: &[u8], time: u64) -> Result<String, String> {
    let t = time / TIME_STEP;

    let mut byte_t = Vec::new();
    byte_t.write_u64::<BigEndian>(t).unwrap();

    hotp::hotp(secret, &byte_t)
}

// UNIX time からの経過秒数を返す
fn current_time() -> Result<u64, String> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => Ok(n.as_secs()),
        Err(_) => Err(String::from("SystemTime before UNIX EPOCH!")),
    }
}
