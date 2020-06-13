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
            // TODO: refactor, using match and write tests
            if let ("add", Some(add_args)) = profile_args.subcommand() {
                profile_add(&mut mfa, add_args)
            }
            if let ("list", Some(_)) = profile_args.subcommand() {
                profile_list(&mfa)
            }
            if let ("remove", Some(remove_args)) = profile_args.subcommand() {
                profile_remove(&mut mfa, remove_args)
            }
        }
        ("show", Some(show_args)) => show(&mfa, show_args),
        _ => println!("{}", args.usage()),
    }

    // TODO: do exit(0) here.
}

// オプション
fn build_option_parser<'a, 'b>() -> App<'a, 'b> {
    App::new("MFA CLI")
        .version(VERSION)
        .about("MFA CLI is MFA code manager.")
        .long_about("It's a MFA code manager.  You can manage MFA accounts and its secret code in command line.")
        .usage("mfa-cli [SUBCOMMAND]\n\nYou can get help by running this command.\n$ mfa-cli help")
        .subcommand(
            SubCommand::with_name("profile")
                .about("You will manage profiles.")
                .long_about("You will manage profiles. Profile is unit of name and secret key pair. You can use profile to manage secret keys. You can register profile, list up profiles, remove profile.")
                .subcommand(
                    SubCommand::with_name("add")
                        .about("Add a new profile")
                        .arg(
                            Arg::with_name("account_name")
                                .takes_value(true)
                                .required(true)
                                .help("Enter a profile name as a label to manage your secret key.")
                                .value_name("ACCOUNT_NAME"),
                        )
                        .arg(
                            Arg::with_name("key")
                                .takes_value(true)
                                .required(true)
                                .help("Enter the secret key that be provided by AWS IAM.")
                                .value_name("SECRET"),
                        ),
                )
                .subcommand(SubCommand::with_name("list").about("Show registered profile list."))
                .subcommand(
                    SubCommand::with_name("remove")
                        .about("Remove any profile")
                        .arg(
                            Arg::with_name("profile_name")
                                .takes_value(true)
                                .required(true)
                                .help("Enter a profile name that you want to remove.")
                                .value_name("PROFILE"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("show") // TODO: change sub command name to "code"
                .about("Show MFA code for the profile.")
                .arg(
                    Arg::with_name("watch")
                        .short("-w")
                        .long("--watch")
                        .help("After showing code, watch for changes."),
                )
                .arg(
                    Arg::with_name("profile_name")
                        .takes_value(true)
                        .required(true)
                        .help("Enter the profile name you want to check.")
                        .value_name("PROFILE"),
                ),
        )
}

fn profile_add(mfa: &mut Mfa, add_args: &ArgMatches) {
    let account_name = add_args.value_of("account_name").unwrap();
    let key = add_args.value_of("key").unwrap();
    if let Err(err) = mfa.register_profile(account_name, key) {
        eprintln!("failed to registring profile: {}", err);
        process::exit(3);
    };

    dump_config(mfa);

    println!("Added new profile");
    process::exit(0);
}

fn profile_list(mfa: &Mfa) {
    println!();
    for profile in mfa.list_profiles() {
        print!(" {}", profile);
    }
    println!();
    process::exit(0);
}

fn profile_remove(mfa: &mut Mfa, remove_args: &ArgMatches) {
    let account_name = remove_args.value_of("profile_name").unwrap();

    if let Err(err) = mfa.remove_profile(account_name) {
        eprintln!("failed remove profile: {}", err);
        process::exit(5);
    }

    dump_config(mfa);
}

// call Mfa#dump()
// exit process with code 3 if failed dump.
fn dump_config(mfa: &Mfa) {
    if let Err(err) = mfa.dump() {
        eprintln!("failed to dump config: {}", err);
        process::exit(3);
    }
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
