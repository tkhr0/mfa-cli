extern crate base32;
extern crate serde;
extern crate toml;

use serde::Deserialize;
use serde::Serialize;

// 設定
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    profiles: Vec<Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn push_profile(&mut self, profile: Profile) {
        // TODO: test name duplication
        self.profiles.push(profile)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Profile> {
        for profile in &self.profiles {
            if *profile.get_name() == *name {
                return Some(&profile);
            }
        }

        None
    }

    // Serialize to strings
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        match toml::to_vec(&self) {
            Ok(data) => Ok(data),
            Err(err) => Err(err.to_string()),
        }
    }

    // Deserialize config from strings
    pub fn deserialize(&mut self, content: Vec<u8>) -> Result<(), String> {
        match toml::from_slice(&content) {
            Ok(config) => {
                *self = config;
                return Ok(());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

// MFA の設定
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Profile {
    name: String,
    secret: String,
}

impl Profile {
    pub fn new(name: &str, secret: &str) -> Self {
        Profile {
            name: name.to_string(),
            secret: secret.to_string(),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    // returns decoded secret
    pub fn get_secret(&self) -> Option<Vec<u8>> {
        base32::decode(base32::Alphabet::RFC4648 { padding: true }, &self.secret)
    }
}
