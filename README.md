# Description

This is a bash and zsh shell tool for maintaining AWS credentials in one or more shells and switching between AWS accounts.

# Getting started using this tool

Requirements:
* Clone the repo or download only the `session-tool.sh` file.
* python and pip installed
* Install the [AWS Command Line tools](https://aws.amazon.com/cli/). AWS official [installation documentation](https://docs.aws.amazon.com/cli/latest/userguide/installing.html). Both AWS CLI version 1 and version 2 are supported. For new installs, version 2 is recommended. 
* Terraform is required, since session-tool contains a wrapper for it to enforce git practices.
* Know the bucket name where your organizations roles are defined
* Session tool is a bash tool, but on Mac OSX zsh is also supported.

Log in to your AWS account and download a set of API keys. Save the csv file to your computer.

```sh
source ./session-tool.sh
get_session -i <api keys csv file> -b <bucket name> -d
get_session -s <MFACODE>
get_console_url <TAB>
assume_role <TAB>
```

In order to use session tool with zsh, you will have to add the following statement to your .zshrc file
```sh
autoload -Uz compinit
compinit
source PATH-TO-SESSION-TOOL/session-tool.sh
```
Replace PATH-TO-SESSION-TOOL with your path to session-tool.


# Synopsis

```sh
source session-tool.sh
```
This can be added to your `.profile`, `.bashrc` or similar.

# Usage

The session-tool.sh shell function definition file contains commands
for managing your AWS session credentials. This is useful for `terraform` and
`aws` cli commands.

## get_session

`get_session [-h] [-s] [-r] [-l] [-c] [-d|-u] [-v] [-i <file> -b <bucket>|-e] [-p <profile>] [<MFA token>]`


* `<MFA token>`  Your one time token. If not provided, and you provided
                 the -s option, the current credentials are stored.
* `-p <profile>` The aws credentials profile to use as an auth base.
                 The provided profile name will be cached, and be the
                 new default for subsequent calls to get_session.
                 Current cached profile: master
                 To avoid having to enter a profile every time, you can
                 use 'aws configure set default.session_tool_default_profile <PROFILE>'
* `-s`           Save the resulting session to persistent storage
                 for retrieval by other shells. You will be prompted
                 twice for a passphrase to protect the stored credentials.
                 Note that storing with an empty passphrase does not work.
* `-r`           Restore previously saved state. You will be promptet for
                 the passphrase you stated when storing the session.
* `-l`           List currently stored sessions including a best guess on
                 when the session expires based on file modification time.
* `-c`           Resets session, removing all environment variables.
* `-d`           Download a list of organization-wide roles to a profile-
                 specific file ~/.aws/[profile]_session-tool_roles.cfg
                 These entries can be overwritten in ~/.aws/[profile]_roles.cfg
                 Fetching is done before getting the session token, using only
                 the permissions granted by the profile.
                 Upstream location and name of the roles list are configurable.
                 Cannot be combined with other options.
* `-u`           Uploads ~/.aws/[profile]_session-tool_roles.cfg to the
                 configured location. Requires more priviledges than download,
                 so is usually done after assume-role. Cannot be combined with
                 other options.
* `-v`           Verifies that the current session (not profile) is valid
                 and not expired.
* `-i <file>`    Import csv file containing api key into your aws profile.
                 This will create or replace your api key in the awsops profile.
                 Also used to import from the output generated by the below export.
* `-e`           Export. Output a command line suitable for import on another host.
* `-b <bucket>`  Set bucket name during import for roles file.
* `-h`           Print this usage.

This command will on a successful authentication return session credentials
for the Basefarm main account. The credentials are returned in the form of
environment variables suitable for the aws and terraform cli. The returned
session has a duration of 12 hours.

At least one of -s, -r or MFA token needs to be provided.

Session state is stored in `~/.aws/<profile>.aes`, encrypted with a passphrase.

## assume_role

`assume_role [-h] [-l] <role alias>`

* `-h`          Print this usage.
* `-l`          List available role aliases.
* `role alias`  The alias of the role to assume. The alias name will be cached,
                so subsequent calls to get_console_url will use the cached value.

This command will use session credentials stored in the shell
from previous calls to get_session The session credentials are
then used to assume the given role.

The session credentials for the assumed role will replace the
current session in the shell environment. The only way to retrieve
the current session after an assume_role is to have stored your
session using get_session with the -s option and then to
import them again using get_session -r command.

The assumed role credentials will only be valid for one hour,
this is a limitation in the underlaying AWS assume_role function.

The selected role alias will be cached in the AWS_ROLE_ALIAS environment
variable, so you do not have to provide it on subsequent calls to assume_role.

Roles are configured in locally in ~/.aws/awsops_roles.cfg, and
organization-wide in ~/.aws/awsops_session-tool_roles.cfg. The format of that file
is as follows. Comment lines begin with #. No other type of comments
are allowed. One line per role and each line is space separated.
The role alias is a name you choose as a shortname for the role.
external_id is optional.

Alias role_arn session_name external_id

Example:
```
# Roles for assume_role
# Alias role_arn session_name external_id
bf-awsopslab-admin arn:aws:iam::1234567890:role/admin bf-awsopslab-admin BF-AWSOpsLab
foo-test arn:aws:iam::0987654321:role/admin bf-awsopslab-admin
```

## get_console_url

`get_console_url [-h] [-l] [-o|-d] [-u <url>] <role alias>`

* `-h`          Print this usage.
* `-l`          List available role aliases.
* `-o`          Open URL in browser using a role specific profile.
* `-d`          Open URL in browser using the Default profile.
* `-u <url>`    Open the specific URL and not the default AWS dashboard.
* `role alias`  The alias of the role that will temporarily be assumed.
                The alias name will be cached, so subsequent calls to
                assume_role or get_console_url will use the cached value.
                Current cached default: <no cached value>

This command will use session credentials stored in the shell from a previous
call to get_session The session credentials are then used to temporily assume
the given role for the purpose of obtaining the console URL.

After this, the session credentials from a previous call to get_session or
assume_role will be restored. The console URL will only be valid for one hour,
this is a limitation in the underlaying AWS assume_role function.

The -o and -d options are currently only supported on Mac OS and Linux and
only using the Chrome browser. You can select which browser binary to use
by setting the session-tool_chrome configuration parameter in your ~/.aws/config file:
```
  aws configure set session-tool_chrome "/Applications/Google Chrome.app" --profile awsops
  aws configure set session-tool_chrome "/snap/bin/chromium" --profile awsops
```

See also: get_session, assume_role. The help for assume_role has more
information about roles definitions and files.

## rotate_credentials

`rotate_credentials [-p PROFILE] [-y|-n] [-t]`

This command will rotate API keys and optionaly also set a new password.

* `-p profile`   Which AWS credentials profile should be rotated.
                 If not specified, the default profile for session-tool will be used.
                 Otherwise, the profile named 'default' will be used.
* `-t`           Rotate both sets of keys. One set will be stored in the profile,
                 the other set shown on the terminal. More info in the wiki.
* `-y`           Yes, password should also changed.
* `-n`           No, password should not be changed.
                 If neither -y nor -n is specified, you will be asked whether or not.
                 password should be changed.

After API key rotation, the command will output a command that can be ran on other hosts
to import the new API key.

## aws-assume-role

`aws-assume-role profile role_alias MFA_token`

This command combines `get_session`, `assume_role` and `get_console_url`.
It is included only to provide backwards compatibility.

## Terraform wrapper
This tool includes a wrapper for terraform that enforces commitment of code in git before you can run `terraform apply` in a folder.

This is enabled by default but can be disabled by doing `aws configure set disable_git_check true --profile [profile]`

It can also be disabled in just your working directory by creating an empty file called `disable_git_check`

If you want to disable it globally for the default AWS profile, do `aws configure set disable_git_check true --profile default`

To re-enable, remove disable_git_check from `~/.aws/config`

Terraform has a `chdir` flag you can set to change directories before applying. When using this wrapper, this is not supported.
# Files

## ~/.aws/[profile]_session-tool_roles.cfg

This file contains the predefined roles that you may assume given the credentials
in your profile, assuming you are member of the proper groups.  
Updates to this file can be retrieved using `get_session -d`. 

## ~/.aws/[profile]_roles.cfg
This file contains your personalized overrides and additions to `[profile]_session-tool_roles.cfg`
Lines starting with a # are treated as comments. All other
lines must contain a roles definition line. Each line is a space separated
list containing these elements:

```
alias role_arn session_name external_id
```
* `alias`A random name you assign to this role_arn.
* `role_arn` The aws arn of the role you want to assume.
* `session_name` A tag that is added to your login trail.
* `external_id` The external ID assisiated with this role.

The tree first are mandatory, while `external_id` is optional, end the line after
`session_name` if `external_id` is not provided.


# Prerequisites

This tool supports both AWS CLI version 1 and 2.

For AWS CLI v1 you must have an up-to-date version of the AWS CLI installed on top of Python 3.

For AWS CLI v2 you only need it installed.

You must have an IAM user with credentials profile stored in your `~/.aws/credentials` file.
This is usually accompished by importing your credentials from AWS using the import (`-i` option) function
of session tool.

The list of roles are downloaded (`-d`) from an S3 bucket configured using the `-b` option when
setting up session tool using the import command (`-i`).

By default session tool will create a profile called `awsops`. Other profiles in your aws envrionment
can co-exist without interference.

Various external dependecies:

* `openssl`   Used to encrypt/decrypt session state to file.
              Only needed if you use the -s or -r
              options to get_session command.
* `date`      On Max OSX it uses the nativ date command.
              On Linux it assumes a GNU date compatible version.
* `aws`       The aws CLI must be avialable and in the PATH.
* `curl`      Used only for getting console URL.
* `python`    Used for normalizing JSON.
* `json.tool` Python library for parsing JSON.
* `test`, `grep`, `egrep`, `awk` and `sed`.

# Environment variables

The tool export to the current shell a lot of variables. Some are required for
`aws` and `terraform` cli support, others are maintained for the benefit of
the user and some are needed by the tool itself.

Required for cli access to aws resources:
* `AWS_SESSION_TOKEN`
* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY_ID`

Maintained for the user and need the for the tool itself:
* `AWS_SESSION_TOOL` Full path and filename of the session tool itself.
* `AWS_PROFILE` The name of the credentials profile. Not needed to auth with the above credentials.
* `AWS_USER` The arn of the current authenticated user.
* `AWS_SERIAL` The arn of the MFA instance for the current user.
* `AWS_ROLE_ALIAS` The alias of the last used role.
* `AWS_EXPIRATION` The time when the current session expires as received from aws (usualy in UTC).
* `AWS_EXPIRATION_S` The time when the current session expires in seconds since the epoch.
* `AWS_EXPIRATION_LOCAL` The time when the current session expires in the current locale.

# Example workflow

These examples assume that you already have added the session-tool.sh to your
.profile (or similar) and that the AWS CLI is installed.

Initial setup consists of configuring an AWS profile and adding credentials to it:

```sh
get_session -i <api keys csv file> -b <bucket name> -d
```

Note that the `-d` flag is used to ensure that organization-wide roles are updated.

The user starts by initializing a session, providing his MFA token:

```sh
get_session 123456
```

The user now has his environment populated with AWS variables that are
suitable to for example run terraform (with assume_role) or AWS command line operations.

The user then needs to open another terminal and have the credentials follow him.
First, the user must then store the existing credentials to file:

```sh
get_session -s
```
The user is prompted twice for the passphrase to protect the stored credentials.

> The user can also provide the `-s` option during the initial authentication
> (using his MFA token), saving him this step.

Then the user can open *another terminal* and restore/import the stored
credentials:
```sh
get_session -r
```

Now the user want's to assume a role within a specific account and
perform some `aws` cli commands:
```sh
assume_role -l
assume_role <role name>
aws iam list-users
```
Then he need to access the AWS management console:
```sh
get_console_url <role name>
```
The returned URL can then be pasted into a browser to gain temporary access to
the management console in the context of the assumed account.  

At any time (both for the Basefarm main account session and the assume_role
session) the user can query the AWS_EXPIRATION_LOCAL variable to get the end
time of the current session.  

Once the assume_role session is expired (after one hour), the credentials are no
longer valid and the user must either re-authenticate or restore (`-r`) a previously
saved session.

## (Long) Example with multiple calls to assume_role  

Since we store a copy of the credentials returned by get_session, we can re-use them for doing
multiple calls of assume_role and get_console_url:
```sh
$ get_session -c
$ get_session 123456
$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
$ assume_role <role1>
$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
$ assume_role <role2>
$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
$ get_console_url <role>
https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=https%3a%2f%2fconsole.aws.amazon.com%2f&SigninToken=xmnh8ELFeXJRaz-qV9jOOVE_m1kqBOu-l1LyabMK7Hc1Sr3EM1HungasdhaskdhjkoBmFObn0DfkJ9Kko.....
$ assume_role <role I do not have access to>

An error occurred (AccessDenied) when calling the AssumeRole operation: Not authorized to perform sts:AssumeRole
ERROR: Unable to obtain session
```  
# Known issues  

* If you do not have a default profile or you change the profile name to one that does not exists in your credentials file, aws cli commands will fail. You need to unset the AWS_PROFILE variable or use these tools to set a new value: `get_session -p <profile> <mfa>`.
* The assume_role command is only able to create sessions that last for one hour. This is an AWS limitation. Once the session has expired, you must re-authenticate or manually restore a previously saved session.
* It is considered best practice to use the built-in assume-role support in terraform, so for terraform purposes you would only use the get_session command. ... and maybe get_console_url when you have trouble figuring out what just got applied

# Authors  
Initial work by [Daniel Abrahamsson](https://github.com/danabr) and [Bent Terp](https://github.com/bentterp), adapted and re-worked by [Bjørn Røgeberg](https://github.com/bjornrog) and [Bent Terp](https://github.com/bentterp).

# Feedback  

Please open an issue if you have some feedback for us.  

# License  

This software is available under the MIT license, as included in the LICENSE file.  
