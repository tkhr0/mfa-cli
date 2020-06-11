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
    pub fn new_profile(&mut self, name: &str, secret: &str) {
        self.push_profile(Profile::new(name, secret));
    }

    fn push_profile(&mut self, profile: Profile) {
        // TODO: test name duplication
        self.profiles.push(profile)
    }

    // Get the decoded secret value with a profile name.
    pub fn get_secret_by_name(&self, name: &str) -> Option<Vec<u8>> {
        if let Some(profile) = self.find_by_name(name) {
            return profile.get_secret();
        }

        None
    }

    // Remove a profile.
    pub fn remove_profile(&mut self, name: &str) -> Result<(), String> {
        let mut index: Option<usize> = None;
        self.profiles.iter().enumerate().for_each(|(i, profile)| {
            if profile.name == name {
                index = Some(i);
                return;
            }
        });

        match index {
            Some(i) => {
                self.profiles.remove(i);
                Ok(())
            }
            _ => Err(format!("Can't find this profile: {}", name)),
        }
    }

    fn find_by_name(&self, name: &str) -> Option<&Profile> {
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
                Ok(())
            }
            Err(err) => Err(err.to_string()),
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

#[test]
fn serialize_profile() {
    let profile = Profile::new("test", "secret");
    let expected = b"name = \"test\"\nsecret = \"secret\"\n";

    assert_eq!(toml::to_vec(&profile).unwrap(), expected);
}

#[test]
fn serialize_config() {
    let config = Config {
        profiles: vec![Profile::new("test", "secret")],
    };
    let expected = r#"[[profiles]]
name = "test"
secret = "secret"
"#;

    assert_eq!(
        String::from_utf8(config.serialize().unwrap()).unwrap(),
        expected
    );
}

#[test]
fn deserialize_config() {
    let string_config = b"[[profiles]]\nname = \"test\"\nsecret = \"secret\"\n ".to_vec();
    let mut config: Config = Default::default();

    config.deserialize(string_config).unwrap();

    assert_eq!(config.profiles.len(), 1);
    assert_eq!(config.profiles[0].name, "test");
    assert_eq!(config.profiles[0].secret, "secret");
}
