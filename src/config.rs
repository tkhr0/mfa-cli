extern crate base32;
extern crate regex;
extern crate serde;
extern crate toml;

use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    IllegalCharacter(&'static str), // A field contains illegal character.
    TooShortLength(&'static str),   // The length of the value of a field is too short.
    TooLongLength(&'static str),    // The length of the value of a field is too long.
    Deplication(&'static str),      // The value of a field is already registered.
    Requires(&'static str),         // A field must have any value.
}

type ValidationResult = Result<(), ValidationError>;

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IllegalCharacter(msg)
            | Self::TooShortLength(msg)
            | Self::TooLongLength(msg)
            | Self::Deplication(msg)
            | Self::Requires(msg) => write!(f, "{}", msg),
        }
    }
}

// 設定
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    profiles: Vec<Profile>,
}

impl Config {
    pub fn new_profile(&mut self, name: &str, secret: &str) -> ValidationResult {
        self.push_profile(Profile::new(name, secret))
    }

    fn push_profile(&mut self, profile: Profile) -> ValidationResult {
        match self.validate_profile(&profile) {
            Ok(_) => {
                // TODO: test name duplication
                self.profiles.push(profile);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn validate_profile(&self, profile: &Profile) -> ValidationResult {
        if self.find_by_name(&profile.name).is_some() {
            return Err(ValidationError::Deplication("This name already exists."));
        }

        profile.is_vaild()
    }

    // Get the decoded secret value with a profile name.
    pub fn get_secret_by_name(&self, name: &str) -> Option<Vec<u8>> {
        if let Some(profile) = self.find_by_name(name) {
            return profile.get_secret();
        }

        None
    }

    // Get borrow profiles
    pub fn get_profiles(&self) -> &Vec<Profile> {
        &self.profiles
    }

    // Remove a profile.
    pub fn remove_profile(&mut self, name: &str) -> Result<(), String> {
        let mut index: Option<usize> = None;
        self.profiles.iter().enumerate().for_each(|(i, profile)| {
            if profile.name == name {
                index = Some(i);
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
        self.profiles
            .iter()
            .find(|&profile| *profile.get_name() == *name)
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

    // Validate self fields format.
    // If validation is failed, returns error type and message.
    pub fn is_vaild(&self) -> ValidationResult {
        self.is_valid_name()?;

        self.is_valid_secret()?;

        Ok(())
    }

    // Validate name format.
    //
    // Requires
    //   - 3~20 characters
    //   - Alphabet or Number or Symbol (@-_)
    fn is_valid_name(&self) -> ValidationResult {
        if self.name.len() < 3 {
            return Err(ValidationError::TooShortLength(
                "Name requires at least 3 characters.",
            ));
        }
        if 20 < self.name.len() {
            return Err(ValidationError::TooLongLength(
                "Name requires 20 characters or less.",
            ));
        }

        // alphabet, number and symbol (@-_)
        const VALID_NAME_PATTERN: &str = r"^[[[:alnum:]]_@-]+\z";
        let re = Regex::new(VALID_NAME_PATTERN).unwrap();
        if !re.is_match(&self.name) {
            return Err(ValidationError::IllegalCharacter(
                "Name can contain only alphabet, number and symbol (@-_) .",
            ));
        }

        Ok(())
    }

    // Validate a secret field format.
    //
    // Requires
    //   - doesn't blank
    fn is_valid_secret(&self) -> ValidationResult {
        if self.secret.is_empty() {
            return Err(ValidationError::Requires("Secret must be present."));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn push_profile_validation_when_name_duplicates() {
        let mut config: Config = Default::default();
        config.new_profile("test", "a").unwrap();
        let second_time = config.new_profile("test", "");

        assert!(second_time.is_err());
    }

    #[test]
    fn push_profile_validation_when_name_contains_multi_byte_char() {
        let mut config: Config = Default::default();
        let result = config.new_profile("あ", "");

        assert_eq!(
            result,
            Err(ValidationError::IllegalCharacter(
                "Name can contain only alphabet, number and symbol (@-_) ."
            ))
        );
    }

    #[test]
    fn push_profile_validation_when_name_contains_symbols_other_than_hyphen_and_underscore_and_at_sign(
    ) {
        let mut config: Config = Default::default();
        let result = config.new_profile("!# $%&", "");

        assert_eq!(
            result,
            Err(ValidationError::IllegalCharacter(
                "Name can contain only alphabet, number and symbol (@-_) ."
            ))
        );
    }

    #[test]
    fn push_profile_validation_when_name_contains_approved_symbols() {
        let mut config: Config = Default::default();
        let result = config.new_profile("-_@", "secret");

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn push_profile_validation_when_name_is_too_short() {
        let mut config: Config = Default::default();
        let result = config.new_profile("ab", "");

        assert_eq!(
            result,
            Err(ValidationError::TooShortLength(
                "Name requires at least 3 characters."
            ))
        );
    }
    #[test]
    fn push_profile_validation_when_name_is_too_long() {
        let mut config: Config = Default::default();
        let result = config.new_profile(&"a".repeat(21), "");

        assert_eq!(
            result,
            Err(ValidationError::TooLongLength(
                "Name requires 20 characters or less."
            ))
        );
    }

    #[test]
    fn push_profile_validation_when_secret_is_blank() {
        let mut config: Config = Default::default();
        let result = config.new_profile("aaa", "");

        assert_eq!(
            result,
            Err(ValidationError::Requires("Secret must be present."))
        );
    }
}
