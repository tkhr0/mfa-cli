extern crate digest;
extern crate hmac;
extern crate sha1;

use digest::generic_array::typenum::U20;
use digest::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type OutputSize = U20;
type HmacSha1 = Hmac<Sha1>;

// HMAC-SHA-1 を計算する
pub fn gen_hmac_sha1(key: &[u8], input: &[u8]) -> Result<GenericArray<u8, OutputSize>, String> {
    let mut mac = match HmacSha1::new_from_slice(key) {
        Ok(mac) => mac,
        Err(err) => return Err(format!("{}", err)),
    };

    mac.update(input);

    Ok(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(ga: &GenericArray<u8, U20>) -> String {
        let mut result = String::from("");

        for c in ga.iter() {
            result.push_str(&format!("{:02x}", c))
        }

        result
    }

    #[test]
    fn hmacsha1() {
        let code = gen_hmac_sha1(b"SGVsbG8gV29ybGQ=", b"1234").unwrap();

        assert_eq!(to_hex(&code), "780b7ebfa252b52192f25e4e48929f08a8772c72");
    }

    #[test]
    fn rfc_4226_hmacsha1_0() {
        let code = gen_hmac_sha1(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(to_hex(&code), "cc93cf18508d94934c64b65d8ba7667fb7cde4b0")
    }
    #[test]
    fn rfc_4226_hmacsha1_1() {
        let code = gen_hmac_sha1(b"12345678901234567890", &[0_u8, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        assert_eq!(to_hex(&code), "75a48a19d4cbe100644e8ac1397eea747a2d33ab")
    }
}
