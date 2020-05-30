use super::hotp;
use byteorder::{BigEndian, WriteBytesExt};
use std::time::SystemTime;

const TIME_STEP: u64 = 30;
const TOTP_DIGITS: u8 = 6;

// TOTP を現在時刻から計算する
pub fn totp(secret: &[u8]) -> Result<String, String> {
    match current_time() {
        Ok(current_time) => gen_totp(secret, current_time, TOTP_DIGITS),
        Err(err) => return Err(err),
    }
}

// TOTP を任意の時刻で計算する
fn gen_totp(secret: &[u8], time: u64, digits: u8) -> Result<String, String> {
    let t = time / TIME_STEP;

    let mut byte_t = Vec::new();
    byte_t.write_u64::<BigEndian>(t).unwrap();

    hotp::hotp(secret, &byte_t, digits)
}

// UNIX time からの経過秒数を返す
fn current_time() -> Result<u64, String> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => Ok(n.as_secs()),
        Err(_) => Err(String::from("SystemTime before UNIX EPOCH!")),
    }
}

// from RFC6238
// +---+-------------+--------------+------------------+----------+--------+
// | # |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
// |---+-------------+--------------+------------------+----------+--------+
// | 1 |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
// |   |             |   00:00:59   |                  |          |        |
// | 2 |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
// |   |             |   01:58:29   |                  |          |        |
// | 3 |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
// |   |             |   01:58:31   |                  |          |        |
// | 4 |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
// |   |             |   23:31:30   |                  |          |        |
// | 5 |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
// |   |             |   03:33:20   |                  |          |        |
// | 6 | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
// |   |             |   11:33:20   |                  |          |        |
// +---+-------------+--------------+------------------+----------+--------+

#[test]
fn rfc_6238_1() {
    let totp = gen_totp(b"12345678901234567890", 59, 8).unwrap();
    assert_eq!(totp, "94287082");
}

#[test]
fn rfc_6238_2() {
    let totp = gen_totp(b"12345678901234567890", 1111111109, 8).unwrap();
    assert_eq!(totp, "07081804");
}

#[test]
fn rfc_6238_3() {
    let totp = gen_totp(b"12345678901234567890", 1111111111, 8).unwrap();
    assert_eq!(totp, "14050471");
}

#[test]
fn rfc_6238_4() {
    let totp = gen_totp(b"12345678901234567890", 1234567890, 8).unwrap();
    assert_eq!(totp, "89005924");
}

#[test]
fn rfc_6238_5() {
    let totp = gen_totp(b"12345678901234567890", 2000000000, 8).unwrap();
    assert_eq!(totp, "69279037");
}

#[test]
fn rfc_6238_6() {
    let totp = gen_totp(b"12345678901234567890", 20000000000, 8).unwrap();
    assert_eq!(totp, "65353130");
}
