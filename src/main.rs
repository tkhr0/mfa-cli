extern crate clap;
extern crate mfa_cli;

use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};
use mfa_cli::mfa::Mfa;
use mfa_cli::totp;
use std::io::{self, Write};
use std::process;
use std::{thread, time};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[clap(name = "MFA CLI")]
#[clap(version = VERSION)]
#[clap(about = "MFA CLI is MFA code manager.")]
#[clap(
    long_about = "It's a MFA code manager. You can manage MFA accounts and its secret code in command line."
)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(subcommand)]
    #[clap(
        long_about = "You will manage profiles. Profile is unit of name and secret key pair. You can use profile to manage secret keys. You can register profile, list up profiles, remove profile."
    )]
    /// You will manage profiles.
    Profile(Profile),
    /// Show MFA code for the profile.
    Show(Show),
}

#[derive(Subcommand)]
enum Profile {
    /// Add a new profile
    Add(Add),
    /// Show registered profile list.
    List,
    /// Remove any profile
    Remove(Remove),
}

#[derive(Args)]
struct Show {
    #[clap(value_parser)]
    /// Enter the profile name you want to check.
    profile: String,
    #[clap(short, long, action = ArgAction::SetFalse)]
    /// After showing code, watch for changes.
    watch: bool,
}

#[derive(Args)]
struct Add {
    #[clap(value_parser)]
    /// Enter a profile name as a label to manage your secret key.
    account_name: String,
    #[clap(value_parser)]
    /// Enter the secret key that be provided by AWS IAM.
    key: String,
}

#[derive(Args)]
struct Remove {
    #[clap(value_parser)]
    /// Enter a profile name that you want to remove.
    profile: String,
}

fn main() {
    let mut mfa = match Mfa::new() {
        Ok(mfa) => mfa,
        Err(err) => {
            eprintln!("failed to initialize: {}", err);
            process::exit(1);
        }
    };

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Profile(profile)) => match profile {
            Profile::Add(args) => profile_add(&mut mfa, args),
            Profile::List => profile_list(&mfa),
            Profile::Remove(args) => profile_remove(&mut mfa, args),
        },
        Some(Commands::Show(args)) => show(&mfa, args),
        &None => Cli::command().print_long_help().unwrap(),
    };

    process::exit(0);
}

fn profile_add(mfa: &mut Mfa, args: &Add) {
    if let Err(err) = mfa.register_profile(&args.account_name, &args.key) {
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

fn profile_remove(mfa: &mut Mfa, args: &Remove) {
    if let Err(err) = mfa.remove_profile(&args.profile) {
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

fn show(mfa: &Mfa, args: &Show) {
    let profile = &args.profile;

    let secret = match mfa.get_secret_by_name(&args.profile) {
        Some(secret) => secret,
        None => {
            eprintln!("can't get the secret that profile: {}", profile);
            process::exit(4);
        }
    };

    loop {
        let code = match totp::totp(&secret) {
            Ok(code) => code,
            Err(err) => panic!("{}", err),
        };
        print!("{}", code);
        io::stdout().flush().unwrap();

        if args.watch {
            thread::sleep(time::Duration::from_secs(1));
            print!("\r");
        } else {
            println!();
            break;
        }
    }
    process::exit(0);
}
