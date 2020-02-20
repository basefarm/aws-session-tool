# Description

This is a bash and zsh shell tool for maintaining AWS credentials in one or more shells and switching between AWS accounts.

# Getting started using this tool

Requirements:
* Clone the repo or download only the `session-tool.sh` file.
* python and pip installed
* Install the [AWS Command Line tools](https://aws.amazon.com/cli/). AWS official [installation documentation](https://docs.aws.amazon.com/cli/latest/userguide/installing.html).
* Know the bucket name where your organizations roles are defined

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

`get_session [-h] [-s] [-r] [-l] [-c] [-d] [-u] [-p profile] [-i file -b bucket] [MFA token]`

 * `MFA token`    Your one time token. If not provided, and you provided
                  the -s option, the current credentials are stored.
 * `-p profile`   The aws credentials profile to use as an auth base.
                  The provided profile name will be cached, and be the
                  new default for subsequent calls to get_session.
                  Default: awsops
 * `-s`           Save the resulting session to persistent storage
                  for retrieval by other shells. You will be prompted
                  twice for a passphrase to protect the stored credentials.
 * `-r`           Restore previously saved state. You will be prompted for
                  the passphrase you stated when storing the session.
 * `-l`           List currently stored sessions including a best guess on
                  when the session expires based on file modification time.
 * `-c`           Resets session.
 * `-d`           Download a list of organization-wide roles to a profile-
                  specific file ~/.aws/[profile]_session-tool_roles.cfg
	                These entries can be overwritten in ~/.aws/[profile]_roles.cfg
                  Fetching is done before getting the session token, using only
                  the permissions granted by the profile.
                  Upstream location and name of the roles list are configurable.
		  Cannot be combined with other options.
* `-u`            Uploads ~/.aws/[profile]_session-tool_roles.cfg to the
	                configured location. Requires more priviledges than download,
	                so is usually done after assume-role.
			Cannot be combined with other options.
* `-i file`	  Import csv file containing api key into your aws profile.
      		  This will create or replace your api key in the awsops profile.
* `-b bucket`	  Set bucket name during key import for roles file.
* `-h`            Print this usage.

This command will on a successful authentication return
session credentials for the AWS account holding the profile's credentials.
The credentials are returned in the form of environment variables suitable for
the `aws` cli and `terraform`. The returned session has a duration of 12 hours.

At least one of -s, -r or MFA token needs to be provided.

Session state is stored in: `~/.aws/[profile].aes` encrypted with a passphrase.

## assume_role

`assume_role [-h] [-l] [role alias]`

* `-h`          Print this usage.
* `-l`          List available role aliases.
* `role alias`  The alias of the role to assume. The alias name will be cached,
                so subsequent calls to get_console_url will use the cached value.

This command will use session credentials stored in the shell
from previous calls to get_session The session credentials are
then used to assume the given role.

The assumed role credentials will only be valid for one hour,
this is a limitation in the underlaying AWS assume_role function.

The selected role alias will be cached in the AWS_ROLE_ALIAS environment
variable, so you do not have to provide it on subsequent calls to assume_role.

## get_console_url

`get_console_url [-h] [-l] [role alias]`

* `-h`          Print this usage.
* `-l`          List available role aliases.
* `role alias`  The alias of the role to assume. The alias name will be cached,
                so subsequent calls to get_console_url will use the cached value.

This command will use session credentials stored in the shell
from previous calls to get_session. The session credentials are
then used to assume the given role and finally to create
a pre-signed URL for console access.

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

You must have an up-to-date version of the AWS CLI installed on top of Python 3.
You must have an IAM user with credentials profile stored in your `~/.aws/credentials` file.
This is usually done using the `aws configure` command.
The list of roles are downloaded (`get_session -d -p <PROFILENAME>`) from an S3 bucket configured like this: `aws configure set session-tool_bucketname <BUCKETNAME> --profile <PROFILENAME>`. This of course requires that your IAM user credentials allow access to the bucket.  
If you have a profile which you normally use, you can set it as the default choice for session-tool with `aws configure set default.session_tool_default_profile <PROFILENAME>`
These commands assume that you have a profile called *awsops*. You might use a
different name, but must then provide the profile name when initializing
a session.

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
* `AWS_PROFILE` The name of the credentials profile. Not needed to auth with the above credentials.

Maintained for the user and need the for the tool itself:
* `AWS_EXPIRATION_LOCAL` The time when the current session expires in the current locale.
* `AWS_CONSOLE_URL` The URL to the aws console, created by the assume_role command.
* `AWS_CONSOLE_URL_EXPIRATION_LOCAL` The time when the aws console url session expires in the current locale.
* `AWS_USER` The arn of the current authenticated user.
* `AWS_SERIAL` The arn of the MFA instance for the current user.
* `AWS_ROLE_ALIAS` The alias of the last used role.
* `AWS_EXPIRATION` The time when the current session expires as received from aws (in Zulu time).
* `AWS_EXPIRATION_S` The time when the current session expires converted to seconds since the epoch.
* `AWS_CONSOLE_URL_EXPIRATION` The time when the aws console url session expires as received from aws (in Zulu time).
* `AWS_CONSOLE_URL_EXPIRATION_S` The time when the aws console url session expires converted to seconds since the epoch.

# Example workflow

These examples assume that you already have added the session-tool.sh to your
.profile (or similar) and that the AWS CLI is installed.

Initial setup consists of configuring an AWS profile and adding credentials to it:

```sh
aws configure --profile awsops
```

The user starts by initializing a session, providing his MFA token:

```sh
get_session -d 123456
```

Note that the `-d` flag is used to ensure that organization-wide roles are updated.
The user now has his environment populated with AWS variables that are
suitable to for example run terraform (with assume_role).

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

Now the user want's to assume a role within the Basefarm lab environment and
perform some `aws` cli commands:
```sh
assume_role -l
assume_role awsopslab-admin
aws iam list-users
```
Then he need to access the AWS management console:
```sh
get_console_url
```
The returned URL can then be pasted into a browser to gain temporary access to
the management console in the context of the assumed account.  

Because the user first ran the assume_role command, the get_console_url will
just echo the AWS_CONSOLE_URL environment variable and the console session will
only last until the assume_role session expires.  

At any time (both for the Basefarm main account session and the assume_role
session) the user can query the AWS_EXPIRATION_LOCAL variable to get the end
time of the current session.  

Once the assume_role session is expired (after one hour), the credentials are no
longer valid and the user must either re-authenticate or restore a previously
saved session.  

## (Long) Example with multiple calls to assume_role  

Since we store a copy of the credentials returned by get_session, we can re-use them for doing
multiple calls of assume_role and get_console_url:
```sh
[bent@c7vm ~]$ get_session -c
[bent@c7vm ~]$ get_session 123456
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"basefarm-operations"
[bent@c7vm ~]$ assume_role bf-awsopslab-admin
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"bf-awsopslab"
[bent@c7vm ~]$ assume_role bf-awsops-admin
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"basefarm-operations"
[bent@c7vm ~]$ assume_role bf-awsopslab-admin
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"bf-awsopslab"
[bent@c7vm ~]$ get_console_url bf-awsops-admin
https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=https%3a%2f%2fconsole.aws.amazon.com%2f&SigninToken=xmnh8ELFeXJRaz-qV9jOOVE_m1kqBOu-l1LyabMK7Hc1Sr3EM1HungasdhaskdhjkoBmFObn0DfkJ9Kko.....
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"bf-awsopslab"
[bent@c7vm ~]$ assume_role bf-awsopslab-failtest

An error occurred (AccessDenied) when calling the AssumeRole operation: Not authorized to perform sts:AssumeRole
ERROR: Unable to obtain session
[bent@c7vm ~]$ aws iam list-account-aliases | jq ".AccountAliases|.[]"
"bf-awsopslab"
[bent@c7vm ~]
```  
# Known issues  

* If you do not have a default profile or you change the profile name to one that does not exists in your credentials file, aws cli commands will fail. You need to unset the AWS_PROFILE variable or use these tools to set a new value: `get_session -p <profile> <mfa>`.
* The assume_role command is only able to create sessions that last for one hour. This was an AWS limitation. Once the session has expired, you must re-authenticate or manually restore a previously saved session.
* It is considered best practice to use the built-in assume-role support in terraform, so for terraform purposes you would only use the get_session command. ... and maybe get_console_url when you have trouble figuring out what just got applied
* Some AWS CLI commands require Python 3 (https://www.linkedin.com/pulse/aws-cli-requires-python3-bent-terp)

# Authors  
Initial work by [Daniel Abrahamsson](https://github.com/danabr) and [Bent Terp](https://github.com/bentterp), adapted and re-worked by [Bjørn Røgeberg](https://github.com/bjornrog) and [Bent Terp](https://github.com/bentterp).

# Feedback  

Please open an issue if you have some feedback for us.  

# License  

This software is available under the MIT license, as included in the LICENSE file.  
