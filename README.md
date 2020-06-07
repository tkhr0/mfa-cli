# MFA-CLI
A CLI client for MFA

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

## License
This software is released under the MIT License.
