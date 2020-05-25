extern crate serde;
extern crate toml;

use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::fs::{DirBuilder, File};
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;

// 設定ファイルのルートディレクトリ
const SAVE_DIR_NAME: &str = "mfa-cli";
// 設定ファイル名
const SAVE_FILE_NAME: &str = "profile";

// 設定
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    profiles: Vec<Profile>,
}

impl Config {
    pub fn new() -> Self {
        Config { profiles: vec![] }
    }

    // 設定ファイルに書き出す
    pub fn dump(&self, path: &String) -> Result<(), io::Error> {
        let mut file = File::create(path)?;
        let toml = toml::to_vec(&self).unwrap();
        file.write_all(&toml)?;
        file.flush()?;

        Ok(())
    }

    // 設定ファイルを読み込む
    pub fn restore(path: &String) -> Result<Config, io::Error> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let config = toml::from_slice(&buffer).unwrap();
        Ok(config)
    }

    pub fn push_profile(&mut self, profile: Profile) {
        // TODO: test name duplication
        self.profiles.push(profile)
    }

    fn find_by_name(&self, name: String) -> Option<&Profile> {
        for profile in &self.profiles {
            if *profile.get_name() == name {
                return Some(&profile);
            }
        }

        None
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
}

// 初期化処理
// 設定ディレクトリ・ファイルを作成する
//
// XDG_CONFIG_HOME を配置場所とする
pub fn initialize() -> Result<String, String> {
    let config_dir = match env::var("XDG_CONFIG_HOME") {
        Ok(path) => {
            let mut path = PathBuf::from(path);
            path.push(SAVE_DIR_NAME);
            path
        }
        Err(err) => return Err(format!("{}", err)),
    };

    if !config_dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .create(&config_dir)
            .unwrap();
    }

    let mut config_path = config_dir.to_path_buf();
    config_path.push(SAVE_FILE_NAME);
    if !config_path.exists() {
        if let Err(_) = File::create(&config_path) {
            return Err("Can not create config directory.".to_string());
        }
    }

    Ok(config_path.to_str().unwrap().to_string())
}
