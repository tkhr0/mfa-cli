extern crate digest;
extern crate generic_array;
extern crate hmac;
extern crate sha1;

use digest::generic_array::typenum::{U20, U64};
use digest::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type OutputSize = U20;
type HmacSha1 = Hmac<Sha1Engine>;

#[derive(Clone)]
struct Sha1Engine {
    engine: Sha1,
}

impl digest::Input for Sha1Engine {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.engine.update(data.as_ref());
    }
}

impl digest::BlockInput for Sha1Engine {
    type BlockSize = U64;
}

impl digest::FixedOutput for Sha1Engine {
    type OutputSize = U20;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::from(self.engine.digest().bytes())
    }
}

impl digest::Reset for Sha1Engine {
    fn reset(&mut self) {
        self.engine = Sha1::new();
    }
}

impl Default for Sha1Engine {
    fn default() -> Self {
        Self {
            engine: Sha1::new(),
        }
    }
}

// HMAC-SHA-1 を計算する
pub fn gen_hmac_sha1(key: &[u8], input: &[u8]) -> Result<GenericArray<u8, OutputSize>, String> {
    let mut mac = match HmacSha1::new_varkey(key) {
        Ok(mac) => mac,
        Err(err) => return Err(format!("{}", err)),
    };

    mac.input(input);

    Ok(mac.result().code())
}

#[cfg(test)]
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
