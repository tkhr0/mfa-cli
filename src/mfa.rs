use super::config;
use super::totp;
use std::env;
use std::fmt;
use std::fs::{DirBuilder, File};
use std::io::prelude::*;
use std::path::Path;

// 設定ファイルのルートディレクトリ
const SAVE_DIR_NAME: &str = "mfa-cli";
const HIDDEN_SAVE_DIR_NAME: &str = ".mfa-cli";
// 設定ファイル名
const CONFIG_FILE_NAME: &str = "profile";

// for using print Profile
#[derive(Debug)]
pub struct Profile {
    name: String,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Profile {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[derive(Debug, Default)]
pub struct Mfa {
    config: config::Config,
    dump_file: DumpFile,
}

impl Mfa {
    pub fn new() -> Result<Self, String> {
        let mut this = Self {
            config: Default::default(),
            dump_file: Default::default(),
        };

        match this.setup() {
            Ok(_) => Ok(this),
            Err(err) => Err(err),
        }
    }

    // Build new profile and register.
    pub fn register_profile(&mut self, account_name: &str, secret: &str) -> Result<(), String> {
        match self.config.new_profile(account_name, secret) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }

    // Get all of profile list
    pub fn list_profiles(&self) -> Vec<Profile> {
        self.config
            .get_profiles()
            .iter()
            .map(|profile| Profile::new(profile.get_name().to_string()))
            .collect()
    }

    pub fn remove_profile(&mut self, profile_name: &str) -> Result<(), String> {
        self.config.remove_profile(profile_name)
    }

    // Get the decoded secret value with a profile name.
    pub fn get_secret_by_name(&self, profile_name: &str) -> Option<Vec<u8>> {
        self.config.get_secret_by_name(profile_name)
    }

    // Get the authentication code with a profile name.
    pub fn get_code_by_name(&self, profile_name: &str) -> Result<String, String> {
        match self.get_secret_by_name(profile_name) {
            Some(secret) => totp::totp(secret.as_ref()),
            None => Err(format!(
                "can't get the secret that profile: {}",
                profile_name
            )),
        }
    }

    // Dump config to file
    pub fn dump(&self) -> Result<(), String> {
        let config_data = match self.config.serialize() {
            Ok(data) => data,
            Err(err) => return Err(err),
        };

        let mut file = match File::create(self.dump_file.path()) {
            Ok(file) => file,
            Err(err) => return Err(err.to_string()),
        };
        match file.write_all(config_data.as_bytes()) {
            Ok(()) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }

    // Restore config from file
    pub fn restore(&mut self) -> Result<(), String> {
        let mut file = match File::open(self.dump_file.path()) {
            Ok(file) => file,
            Err(err) => return Err(err.to_string()),
        };
        let mut contents = String::new();
        if let Err(err) = file.read_to_string(&mut contents) {
            return Err(err.to_string());
        };

        self.config.deserialize(&contents)
    }

    // Run setup steps.
    //
    // Restore config if a dump file exists already.
    // Otherwise do nothing.
    fn setup(&mut self) -> Result<(), String> {
        // Create save dir
        if !self.dump_file.dir_exists() {
            if let Err(err) = DirBuilder::new()
                .recursive(true)
                .create(self.dump_file.dir_path())
            {
                return Err(err.to_string());
            }
        }

        // nothing to do if it does not exist
        if !self.dump_file.exists() {
            return Ok(());
        }

        if self.dump_file.check() {
            return self.restore();
        }

        Ok(())
    }
}

#[derive(Debug)]
struct DumpFile {
    dir: Box<Path>,
    file_name: &'static str,
}

impl Default for DumpFile {
    fn default() -> Self {
        let path = fetch_dump_path().to_path_buf();

        Self {
            dir: path.into_boxed_path(),
            file_name: CONFIG_FILE_NAME,
        }
    }
}

impl DumpFile {
    // It returns true if dump file exists.
    fn exists(&self) -> bool {
        self.path().exists()
    }

    fn dir_exists(&self) -> bool {
        self.dir_path().exists()
    }

    // Check the dump file state.
    // It returns true if the dump file is restorable condition.
    //
    // Conditions is the file exists, it is file and file size is not empty.
    fn check(&self) -> bool {
        if !self.exists() {
            return false;
        }

        let meta = match self.path().metadata() {
            Ok(meta) => meta,
            Err(_) => return false,
        };

        meta.is_file() && 0 < meta.len()
    }

    fn path(&self) -> Box<Path> {
        let mut path = self.dir.to_path_buf();
        path.push(self.file_name);
        path.into_boxed_path()
    }

    fn dir_path(&self) -> &Path {
        &self.dir
    }
}

// decides directory which dump config file
fn fetch_dump_path() -> Box<Path> {
    if let Some(path) = env_my_home() {
        let mut path = Path::new(&path).to_path_buf();
        path.push(SAVE_DIR_NAME);
        return path.into_boxed_path();
    }

    if let Some(path) = env_xdg_config_home() {
        let mut path = Path::new(&path).to_path_buf();
        path.push(SAVE_DIR_NAME);
        return path.into_boxed_path();
    }

    if let Some(path) = env_home() {
        let mut path = Path::new(&path).to_path_buf();
        path.push(HIDDEN_SAVE_DIR_NAME);
        return path.into_boxed_path();
    }

    if let Ok(mut path) = env::current_dir() {
        path.push(HIDDEN_SAVE_DIR_NAME);
        return path.into_boxed_path();
    }

    panic!("can't find save directory");
}

fn env_my_home() -> Option<String> {
    match env::var("MFA_CLI_CONFIG_HOME") {
        Ok(path) if Path::new(&path).exists() => Some(path),
        Ok(path) if !Path::new(&path).exists() => {
            DirBuilder::new().recursive(true).create(&path).unwrap();
            Some(path)
        }
        _ => None,
    }
}

fn env_xdg_config_home() -> Option<String> {
    match env::var("XDG_CONFIG_HOME") {
        Ok(path) if Path::new(&path).exists() => Some(path),
        _ => None,
    }
}

fn env_home() -> Option<String> {
    match env::var("HOME") {
        Ok(path) if Path::new(&path).exists() => Some(path),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn dump_file_path() {
        let dump_file = DumpFile {
            dir: Path::new("/path/to").to_path_buf().into_boxed_path(),
            file_name: "file",
        };

        let path = dump_file.path();

        assert_eq!(*path.as_ref(), *Path::new("/path/to/file"));
    }

    #[test]
    #[ignore]
    fn setup_config_dir_for_for_xdg_config_home() {
        let config_home = tempfile::tempdir().unwrap();
        env::set_var("MFA_CLI_CONFIG_HOME", config_home.path().to_str().unwrap());

        let _ = Mfa::new();
        assert!(config_home.path().join("mfa-cli").is_dir());
    }

    #[test]
    #[ignore]
    fn setup_config_dir_for_current_dir() {
        let pwd = env::current_dir().unwrap();
        let config_home = tempfile::tempdir().unwrap();

        env::remove_var("MFA_CLI_CONFIG_HOME");
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("HOME");
        let _ = env::set_current_dir(config_home.path());

        let _ = Mfa::new();
        assert!(config_home.path().join(".mfa-cli").is_dir());

        let _ = env::set_current_dir(pwd);
    }

    #[test]
    fn fetch_dump_path_from_env_my_home_when_that_exists() {
        let current_dir = env::current_dir().unwrap();
        let expected = current_dir.join("tests/tmp/mfa-cli");
        env::set_var("MFA_CLI_CONFIG_HOME", current_dir.join("tests/tmp"));

        assert_eq!(*fetch_dump_path(), *expected);
    }

    #[test]
    fn fetch_dump_path_from_env_my_home_when_that_does_not_exist() {
        let current_dir = env::current_dir().unwrap();

        let expected = current_dir.join("tests/tmp/does_not_exist/mfa-cli");
        let config_home_path = current_dir.join("tests/tmp/does_not_exist");
        env::set_var("MFA_CLI_CONFIG_HOME", config_home_path.clone());

        assert_eq!(*fetch_dump_path(), *expected);
        std::fs::remove_dir(config_home_path).unwrap();
    }

    // NOTE: The reason this test is marked as ignore is that environment variables conflict between tests
    //       You have to append single thread option when run tests
    #[test]
    #[ignore]
    fn fetch_dump_path_from_env_xdg_config_home() {
        env::remove_var("MFA_CLI_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", "./tests/tmp");
        assert_eq!(*fetch_dump_path(), *Path::new("./tests/tmp/mfa-cli"));
    }

    #[test]
    fn fetch_dump_path_from_env_home() {
        env::remove_var("MFA_CLI_CONFIG_HOME");
        env::remove_var("XDG_CONFIG_HOME");

        env::set_var("HOME", "./tests/tmp");
        assert_eq!(*fetch_dump_path(), *Path::new("./tests/tmp/.mfa-cli"));
    }

    // NOTE: The reason this test is marked as ignore is that environment variables conflict between tests
    //       You have to append single thread option when run tests
    #[test]
    #[ignore]
    fn fetch_dump_path_from_current_dir() {
        env::remove_var("MFA_CLI_CONFIG_HOME");
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("HOME");

        let expected = env::current_dir().unwrap().join(".mfa-cli");
        assert_eq!(*fetch_dump_path(), expected);
    }

    #[test]
    fn setup_when_there_is_empty_config_file() {
        env::set_var("MFA_CLI_CONFIG_HOME", "tests/tmp/");
        std::fs::create_dir_all("tests/tmp/mfa-cli/").unwrap();
        File::create("tests/tmp/mfa-cli/profile").unwrap();

        assert!(Mfa::new().is_ok());

        std::fs::remove_file("tests/tmp/mfa-cli/profile").unwrap()
    }

    #[test]
    fn test_remove_profile() {
        let mut mfa: Mfa = Default::default();
        mfa.config.new_profile("test", "hoge").unwrap();

        mfa.remove_profile("test").unwrap();
        assert!(mfa.get_secret_by_name("test").is_none());
    }

    #[test]
    fn test_list_profiles() {
        let mut mfa: Mfa = Default::default();
        mfa.config.new_profile("test1", "hoge").unwrap();
        mfa.config.new_profile("test2", "hoge").unwrap();

        let profiles = mfa.list_profiles();
        assert_eq!(profiles.get(0).unwrap().name, "test1");
        assert_eq!(profiles.get(1).unwrap().name, "test2");
        assert!(profiles.get(2).is_none());
    }
}
