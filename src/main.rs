extern crate clap;
extern crate mfa_cli;

use clap::{App, Arg, ArgMatches, SubCommand};
use mfa_cli::mfa::Mfa;
use mfa_cli::totp;
use std::io::{self, Write};
use std::process;
use std::{thread, time};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut mfa = match Mfa::new() {
        Ok(mfa) => mfa,
        Err(err) => {
            eprintln!("failed to initialize: {}", err);
            process::exit(1);
        }
    };

    let args = build_option_parser().get_matches();

    match args.subcommand() {
        ("profile", Some(profile_args)) => {
            if let ("add", Some(add_args)) = profile_args.subcommand() {
                profile_add(&mut mfa, add_args)
            }
        }
        ("show", Some(show_args)) => show(&mfa, show_args),
        _ => println!("{}", args.usage()),
    }
}

// オプション
fn build_option_parser<'a, 'b>() -> App<'a, 'b> {
    App::new("MFA CLI")
        .version(VERSION)
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
                    Arg::with_name("watch")
                        .short("-w")
                        .long("--watch")
                        .help("After showing code, watch for changes"),
                )
                .arg(
                    Arg::with_name("profile_name")
                        .takes_value(true)
                        .required(true)
                        .help("profile name"),
                ),
        )
}

fn profile_add(mfa: &mut Mfa, add_args: &ArgMatches) {
    let account_name = add_args.value_of("account_name").unwrap();
    let key = add_args.value_of("key").unwrap();
    if let Err(err) = mfa.register_profile(account_name, key) {
        eprintln!("failed to dump config: {}", err);
        process::exit(3);
    };
    println!("Added new profile");
    process::exit(0);
}

fn show(mfa: &Mfa, args: &ArgMatches) {
    let profile_name = args.value_of("profile_name").unwrap();
    let is_watch = 0 < args.occurrences_of("watch");

    let secret = match mfa.get_secret_by_name(profile_name) {
        Some(secret) => secret,
        None => {
            eprintln!("can't get the secret that profile: {}", profile_name);
            process::exit(4);
        }
    };

    loop {
        let code = match totp::totp(&secret) {
            Ok(code) => code,
            Err(err) => panic!(err),
        };
        print!("{}", code);
        io::stdout().flush().unwrap();

        if is_watch {
            thread::sleep(time::Duration::from_secs(1));
            print!("\r");
        } else {
            println!();
            break;
        }
    }
    process::exit(0);
}
