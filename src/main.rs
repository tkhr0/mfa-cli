extern crate base32;
extern crate mfa_cli;

use mfa_cli::totp;

fn main() {
    let raw_secret = "AAAAAAA";

    let secret = base32::decode(base32::Alphabet::RFC4648 { padding: true }, raw_secret).unwrap();
    let code = totp::totp(&secret);

    println!("{:?}", code.unwrap());
}
