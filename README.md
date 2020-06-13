# MFA-CLI
A CLI client for MFA


## Install
Download a latest mfa-cli from mfa-cli.zip link on below releases page.
https://github.com/tkhr0/mfa-cli/releases

Then unzip the file and move binary to $PATH dir.

```sh
$ unzip mfa-cli.zip
$ ls ./target/release/mfa-cli
./target/release/mfa-cli

$ mv target/release/mfa-cli /usr/local/bin
$ ls /usr/local/bin/mfa-cli
/usr/local/bin/mfa-cli

$ mfa-cli -V
MFA CLI 0.2.0
```


## Usage
```sh
# Add a new profiles
$ mfa-cli profile add PROFILE_NAME SECRET_CODE

# Show MFA code for the profile
$ mfa-cli show PROFILE_NAME
123456

# After showing code, watch for changes
$ mfa-cli show -w PROFILE_NAME
123456

# Show help
$ mfa-cli help
```

mfa-cli store config to file.
You will manage the directory by env variables.
Here are the values and priorities you can specify.
1. `MFA_CLI_CONFIG_HOME`
1. `XDG_CONFIG_HOME`
1. `HOME`
1. Current directory
   (If mfa-cli couldn't find these values, it will use current directory)

## License
This software is released under the MIT License.
