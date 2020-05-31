use super::config;
use std::env;
use std::fs::{DirBuilder, File};
use std::io::prelude::*;
use std::path::Path;

// 設定ファイルのルートディレクトリ
const SAVE_DIR_NAME: &str = "mfa-cli";
const HIDDEN_SAVE_DIR_NAME: &str = ".mfa-cli";
// 設定ファイル名
const CONFIG_FILE_NAME: &str = "profile";

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

    // Build new profile and save.
    pub fn register_profile(&mut self, account_name: &str, secret: &str) -> Result<(), String> {
        self.config.new_profile(account_name, secret);
        self.dump()
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
        match file.write_all(&config_data) {
            Ok(()) => Ok(()),
            Err(err) => return Err(err.to_string()),
        }
    }

    // Restore config from file
    pub fn restore(&mut self) -> Result<(), String> {
        let mut file = match File::open(self.dump_file.path()) {
            Ok(file) => file,
            Err(err) => return Err(err.to_string()),
        };
        let mut buffer = Vec::new();
        if let Err(err) = file.read_to_end(&mut buffer) {
            return Err(err.to_string());
        };

        self.config.deserialize(buffer)
    }

    // Run setup steps.
    //
    // Initialize config file. Restore config if it exists already.
    fn setup(&mut self) -> Result<(), String> {
        // create config file if it does not exist
        if !self.dump_file.exists() {
            return self.dump_file.create();
        }

        self.restore()
    }
}

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

    // Create config file.
    // If config file exists, it will be truncated.
    fn create(&self) -> Result<(), String> {
        DirBuilder::new().recursive(true).create(&self.dir).unwrap();

        match File::create(&self.path()) {
            Ok(_) => Ok(()),
            Err(_) => Err("Can not create config file".to_string()),
        }
    }

    fn path(&self) -> Box<Path> {
        let mut path = self.dir.to_path_buf();
        path.push(self.file_name);
        path.into_boxed_path()
    }
}

// decides directory which dump config file
fn fetch_dump_path() -> Box<Path> {
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

fn env_xdg_config_home() -> Option<String> {
    match env::var("XDG_CONFIG_HOME") {
        Ok(path) if Path::new(&path).exists() => return Some(path),
        _ => return None,
    }
}

fn env_home() -> Option<String> {
    match env::var("HOME") {
        Ok(path) if Path::new(&path).exists() => return Some(path),
        _ => return None,
    }
}

#[test]
fn dump_file_path() {
    let dump_file = DumpFile {
        dir: Path::new("/path/to").to_path_buf().into_boxed_path(),
        file_name: "file",
    };

    let path = dump_file.path();

    assert_eq!(*path.as_ref(), *Path::new("/path/to/file"));
}
