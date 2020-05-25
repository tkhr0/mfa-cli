extern crate base32;
extern crate clap;
extern crate mfa_cli;

use clap::{App, Arg, SubCommand};
use mfa_cli::config;
use mfa_cli::totp;
use std::process;

fn main() {
    let config_file_path = match config::initialize() {
        Ok(path) => path,
        Err(err) => panic!(err), // TODO: safe exit
    };
    let config = match config::Config::restore(&config_file_path) {
        Ok(config) => config,
        Err(_) => panic!("failed to restore config"), // TODO: safe exit
    };

    let args = build_option_parser().get_matches();

    match args.subcommand() {
        ("profile", Some(profile_args)) => match profile_args.subcommand() {
            ("add", Some(add_args)) => {
                let profile = config::Profile::new(
                    add_args.value_of("account_name").unwrap(),
                    add_args.value_of("key").unwrap(),
                );
                let mut config = config;
                config.push_profile(profile);
                if let Err(_) = config.dump(&config_file_path) {
                    panic!("failed to dump config");
                };
                println!("added new profile");
                process::exit(0);
            }
            _ => {}
        },
        ("show", Some(show_args)) => {
            let profile_name = show_args.value_of("profile_name").unwrap();
            let profile = match config.find_by_name(&profile_name) {
                Some(profile) => profile,
                None => panic!("can't find that profile: {}", profile_name),
            };
            let secret = match base32::decode(
                base32::Alphabet::RFC4648 { padding: true },
                profile.get_secret(),
            ) {
                Some(secret) => secret,
                None => {
                    // TODO: 設定ファイルが空の時
                    panic!("can't load secret for that profile: {}", profile_name)
                }
            };
            let code = match totp::totp(&secret) {
                Ok(code) => code,
                Err(err) => panic!(err),
            };
            println!("{}", code);
            process::exit(0);
        }
        _ => {}
    }
}

// オプション
fn build_option_parser<'a, 'b>() -> App<'a, 'b> {
    App::new("awskey")
        .subcommand(
            SubCommand::with_name("profile")
                .about("profile settings")
                .subcommand(
                    SubCommand::with_name("add")
                        .about("Add a new profile")
                        .help("Add a new profile")
                        .arg(
                            Arg::with_name("account_name")
                                .takes_value(true)
                                .required(true)
                                .help("account name"),
                        )
                        .arg(
                            Arg::with_name("key")
                                .takes_value(true)
                                .required(true)
                                .help("secret"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("show")
                .about("Show MFA code for the profile")
                .arg(
                    Arg::with_name("profile_name")
                        .takes_value(true)
                        .required(true)
                        .help("profile name"),
                ),
        )
}
