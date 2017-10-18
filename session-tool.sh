#!/bin/bash
VERSION=1.4.0
PUBURL="https://raw.githubusercontent.com/basefarm/aws-session-tool/master/session-tool.sh"
#
# Bash utility to
# 1) create a session token in the users environment from existing credentials,
#    optionally using MFA, and optionally storing the session encrypted on disk.
# 2) assuming a role in another AWS account using the session token.
# 3) constructing a URL for assuming a role from the session token, but for accessing
#    the AWS console instead.
# 4) maintain a list of roles from a configurable bucket, using the same credentials.
#
# The utility is supposed to work on both linux and mac.
#
# It should work well with terraform, using the assume_role
# function of the aws provider.
# Please refer to the repository wiki for more documentation regarding
# S3 buckets, policies and rolefiles
#

#
# Prerequisits:
#
#  A working aws credentials profile, default name: awsops
#
#  openssl   Used to encrypt/decrypt session state to file
#            Only needed if you use the --store or --restore
#            options to get_session command
#  date      On Max OSX it uses the nativ date command
#            On Linux it assumes a GNU date compatible version
#  aws       The aws CLI must be avialable and in the PATH
#  curl      Used only for getting console URL
#  python    Used for normalizing JSON
#  json.tool Python library for parsing JSON
#
# test, grep, egrep, awk and sed.
#

# 
# Verify all prerequisites, and initialize arrays etc
# 
_prereq () {
	type curl >/dev/null 2>&1 || echo >&2 "ERROR: curl is not found. session_tools will not work."
	case $OSTYPE in
		darwin*	) _OPENSSL="/usr/bin/openssl";;
		linux*	) _OPENSSL="openssl";;
		cygwin*	) _OPENSSL="openssl";;
		*) echo >&2 "ERROR: Unknown ostype: $OSTYPE" ;;
	esac
	type $_OPENSSL >/dev/null 2>&1 || echo >&2 "ERROR: openssl is not found. session_tools will not work."
	type date >/dev/null 2>&1 || echo >&2 "ERROR: date is not found. session_tools will not work."
	type aws >/dev/null 2>&1 || echo >&2 "ERROR: aws is not found. session_tools will not work."
	type python >/dev/null 2>&1 || echo >&2 "ERROR: python is not found. session_tools will not work."
	python -c "import json.tool" >/dev/null 2>&1 || echo >&2 "ERROR: python json.tool is not found. session_tools will not work."
	type grep >/dev/null 2>&1 || echo >&2 "ERROR: grep is not found. session_tools will not work."
	type egrep >/dev/null 2>&1 || echo >&2 "ERROR: egrep is not found. session_tools will not work."
	type awk  >/dev/null 2>&1 || echo >&2 "ERROR: awk is not found. session_tools will not work."
	type sed >/dev/null 2>&1 || echo >&2 "ERROR: sed is not found. session_tools will not work."
	[[ `ps -fp $$ | grep $$` =~ "bash" ]] || echo >&2 "ERROR: SHELL is not bash. session_tools will not work."

	PUBVERSION="$(curl -s "${PUBURL}" | grep ^VERSION= | head -n 1 | cut -d '=' -f 2)"
	test "${PUBVERSION}" = "${VERSION}" || echo >&2 "WARN: Your version is outdated! You have ${VERSION}, the latest is ${PUBVERSION}"
	
	export AWS_PARAMETERS="AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_USER AWS_SERIAL AWS_EXPIRATION AWS_EXPIRATION_LOCAL AWS_EXPIRATION_S AWS_ROLE_NAME AWS_ROLE_EXPIRATION AWS_ROLE_ALIAS"
}

# Command for creating a session
get_session() {
	
	local OPTIND ; local PROFILE="${AWS_PROFILE:-$(aws configure get default.session_tool_default_profile)}" ; local STORE=false; local RESTORE=false; local DOWNLOAD=false; local VERIFY=false; local UPLOAD=false ; local STOREONLY=false
	# Ugly hack to support people who want to store their sessions retroactively
	if test "$*" = "-s" ; then STOREONLY=true ; fi

	# extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":cdhlp:rsuv" opt ; do
		case "$opt" in
			h		) _get_session_usage ; return 0 ;;
			c		) _aws_reset ; return 0 ;;
			l		)
				local now=$(date +%s)
				for f in `ls ~/.aws/*.aes`; do
					local expiry_s=$(expr $(date -r $f '+%s') + 43200 )
					case $OSTYPE in
						darwin*	) local expiry_l=$(date -r $expiry_s '+%H:%M:%S %Y-%m-%d');;
						linux*	) local expiry_l=$(date -d @${expiry_s} '+%H:%M:%S %Y-%m-%d');;
						cygwin*	) local expiry_l=$(date -d @${expiry_s} '+%H:%M:%S %Y-%m-%d');;
						*				) _echoerr "ERROR: Unknown ostype: $OSTYPE" ; return 1 ;;
					esac
					local profile=$(basename $f .aes)
					if [ $expiry_s -lt $now ]; then
						echo "$profile $expiry_l (EXPIRED)"
					else
						echo "$profile $expiry_l"
					fi
				done
				return 0 ;;
			p		) PROFILE=$OPTARG ;;
			s		) STORE=true ;;
			r		) RESTORE=true ;;
			d		) DOWNLOAD=true ;;
			u		) UPLOAD=true ;;
			v		) VERIFY=true ;;
			\?	) echo "Invalid option: -$OPTARG" >&2 ;;
			:		) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	if ! ${STOREONLY} ; then
		shift $((OPTIND-1))
		if test -z ${PROFILE} ; then
			if aws configure list | grep -q '<not set>' ; then
				_echoerr "ERROR: No profile specified and no default profile configured."
				return 1
			else
				${PROFILE}="$(aws configure list | grep ' profile ' | awk '{print $2}')"
			fi
		fi
		if aws configure list --profile $PROFILE &>/dev/null ; then
			export AWS_PROFILE="${PROFILE}"
		else
			_echoerr "ERROR: The specified profile ${PROFILE} cannot be found."
			return 1
		fi

		# Fetch roles from specified bucket - if it is configured....
		if ${DOWNLOAD} ; then
			if ${UPLOAD} ; then
				_echoerr "ERROR: uploading and downloading are mutually exclusive..."
				return 1
			else
				local ROLEBUCKET
				if ! ROLEBUCKET="$(aws configure get session-tool_bucketname --profile ${AWS_PROFILE})" ; then
					_echoerr "ERROR: No bucket configure to download roles from. Please configure with: aws configure set session-tool_bucketname <BUCKETNAME> --profile ${AWS_PROFILE}"
					return 1
				fi
				local ROLESFILE
				if ! ROLESFILE="$(aws configure get session-tool_rolesfile --profile ${AWS_PROFILE})" ; then
					if ! aws s3 ls "${ROLEBUCKET}/session-tool_roles.cfg" | grep -q session-tool_roles.cfg ; then
						_echoerr "ERROR: There is no rolesfile configured and no session-tool_roles.cfg in ${ROLEBUCKET}. Maybe ${ROLEBUCKET} is not the right bucket, or you need to configure session-tool_rolesfile?"
						return 1
					else
						ROLESFILE="session-tool_roles.cfg"
					fi
				fi
				if ! aws s3 ls "${ROLEBUCKET}/${ROLESFILE}" | grep -q ${ROLESFILE} ; then
					_echoerr "ERROR: There is no ${ROLESFILE} in ${ROLEBUCKET}. Maybe ${ROLEBUCKET} or ${ROLESFILE} is misconfigured?"
					return 1
				fi
				if out="$(aws s3 cp "s3://${ROLEBUCKET}/${ROLESFILE}" ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg 2>&1)" ; then
					return 0
				else
					_echoerr "ERROR: ${out}"
					_echoerr "       Unable to download s3://${ROLEBUCKET}/${ROLESFILE} into ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
					return 1
				fi
			fi
		fi

		if ${UPLOAD} ; then
			if ${DOWNLOAD} ; then
				_echoerr "ERROR: uploading and downloading are mutually exclusive..."
				return 1
			else
				local ROLEBUCKET
				if ! ROLEBUCKET="$(aws configure get session-tool_bucketname --profile ${AWS_PROFILE})" ; then
					_echoerr "ERROR: No bucket configure to upload roles to. Please configure with: aws configure set session-tool_bucketname <BUCKETNAME> --profile ${AWS_PROFILE}"
					return 1
				fi
				if ! ROLESFILE="$(aws configure get session-tool_rolesfile --profile ${AWS_PROFILE})" ; then
					_echoerr "ERROR: please configure the rolesfile to upload: aws configure set session-tool_rolesfile <ROLESFILE> --profile ${AWS_PROFILE}"
					return 1
				fi
				if ! test -r ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg ; then
					_echoerr "ERROR: missing file to upload ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
					return 1
				fi
				aws s3 cp ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg "s3://${ROLEBUCKET}/${ROLESFILE}"
				return 0
			fi
		fi
		
		# Verify session
		if $VERIFY; then
			if [ $# -gt 0 ]; then
				_echoerr "ERROR: Please don't combine verify with other operations."
				return 1
			fi
			if test "${AWS_SESSION_TOKEN}" = "" ; then
				_echoerr "ERROR: No session token found, so there is nothing to validate."
				return 1
			fi

			_pushp TEMP_AWS_PARAMETERS
			_popp STORED_AWS_PARAMETERS
			local response="$(aws sts get-caller-identity 2>&1)"
			_popp TEMP_AWS_PARAMETERS

			if echo "${response}" | grep -q "security token included in the request is expired" ; then
				_echoerr "ERROR: Your session has expired"
				return 1
			else
				return 0
			fi
		fi

		# Restore session
		if $RESTORE; then
			if $STORE; then
				_echoerr "ERROR: You can not both store and restore state in the same run."
				return 1
			fi
			if [ $# -gt 0 ]; then
				_echoerr "ERROR: You can only combine restore with the profile option."
				return 1
			fi

			if [ ! -e ~/.aws/${AWS_PROFILE}.aes ]; then
				_echoerr "ERROR: No saved session found for profile $AWS_PROFILE."
				return 1
			fi

			local CREDENTIALS=$($_OPENSSL aes-256-cbc -d -in ~/.aws/${AWS_PROFILE}.aes)
			if echo "$CREDENTIALS" | egrep -qv "^AWS_"; then
				_echoerr "ERROR: Unable to restore your credentials."
				return 1
			fi

			_pushp TEMP_AWS_PARAMETERS
			_aws_reset
			eval "$CREDENTIALS"
			if ! _session_ok; then
			_popp TEMP_AWS_PARAMETERS
				return 1
			fi

			local NOW=$(date +%s)
			local EXP_HOUR=$(($AWS_EXPIRATION_S + 3600))

			if [ $EXP_HOUR -lt $NOW ]; then
				echo "WARNING: Your $AWS_PROFILE stored session will expire at $AWS_EXPIRATION_LOCAL."
			fi

			local CREDS=$(echo "$CREDENTIALS" | sed 's/^/export /')
			eval "$CREDS"
			for i in ${AWS_PARAMETERS} ; do
				export i
			done
			_pushp STORED_AWS_PARAMETERS
			return 0
		fi

		# Making new session, with optional MFA
		if [ -z "$AWS_USER" ]; then
			_init_aws
		fi
		if [ "${AWS_PROFILE}" != "${AWS_PROFILE_STORED}" ] ; then
			_init_aws
		fi

		_pushp TEMP_AWS_PARAMETERS
		local CREDTXT
		# If there is an MFA, then it should be numeric and used for the sts get-session-token call
		if [ -n "$1" ]; then
			# Verify the MFA token code, AWS currently only support 6 numbers
			local re='^[0-9][0-9][0-9][0-9][0-9][0-9]$'
			if ! [[ "$1" =~ $re ]]; then
				_echoerr "ERROR: MFA token code can only consist of 6 numbers."
				return 1
			fi

			local MFA=$1
			read CREDTXT AWS_ACCESS_KEY_ID AWS_EXPIRATION AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< $(aws --output text --profile $AWS_PROFILE sts get-session-token --serial-number=$AWS_SERIAL --token-code $MFA)

		else
			read CREDTXT AWS_ACCESS_KEY_ID AWS_EXPIRATION AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< $(aws --output text --profile $AWS_PROFILE sts get-session-token)
			_echoerr "# Warning: you did not input an MFA token. Proceed at your own risk."
		fi

		if [ -z "$AWS_SESSION_TOKEN" ]; then
			_echoerr "ERROR: Unable to obtain session"
			_popp TEMP_AWS_PARAMETERS
			return 1
		fi

		case $OSTYPE in
			darwin*)
				export AWS_EXPIRATION_S=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' $AWS_EXPIRATION +%s)
				export AWS_EXPIRATION_LOCAL=$(date -j -r $AWS_EXPIRATION_S);;
			linux*)
				export AWS_EXPIRATION_S=$(date -d $AWS_EXPIRATION +%s)
				export AWS_EXPIRATION_LOCAL=$(date -d $AWS_EXPIRATION);;
			cygwin*)
				export AWS_EXPIRATION_S=$(date -d $AWS_EXPIRATION +%s)
				export AWS_EXPIRATION_LOCAL=$(date -d $AWS_EXPIRATION);;
			*)
			_echoerr "ERROR: Unknown ostype: $OSTYPE"
			_popp TEMP_AWS_PARAMETERS
			return 1;;
		esac

		_pushp STORED_AWS_PARAMETERS
	fi

	# Store if requested
	if $STORE ; then
		touch ~/.aws/${AWS_PROFILE}.aes
		chmod 600 ~/.aws/${AWS_PROFILE}.aes
		$_OPENSSL enc -aes-256-cbc -salt -out ~/.aws/${AWS_PROFILE}.aes <<-EOF
			AWS_USER='$AWS_USER'
			AWS_SERIAL='$AWS_SERIAL'
			AWS_PROFILE='$AWS_PROFILE'
			AWS_SECRET_ACCESS_KEY='$AWS_SECRET_ACCESS_KEY'
			AWS_SESSION_TOKEN='$AWS_SESSION_TOKEN'
			AWS_ACCESS_KEY_ID='$AWS_ACCESS_KEY_ID'
			AWS_EXPIRATION='$AWS_EXPIRATION'
			AWS_EXPIRATION_S='$AWS_EXPIRATION_S'
			AWS_EXPIRATION_LOCAL='$AWS_EXPIRATION_LOCAL'
EOF
	fi
}

assume_role () {
	local OPTIND

	# extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":hl" opt ; do
		case "$opt" in
			h		) _assume_role_usage ; return 0 ;;
			l		) _list_roles ; return 0 ;;
			\?	) echo "Invalid option: -$OPTARG" >&2 ;;
			:		) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))
	if ! _check_exists_rolefiles ; then return 1 ; fi

	_sts_assume_role $* ; return $?

}

get_console_url () {
	local OPTIND

	# extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":hl" opt ; do
		case "$opt" in
			h		) _get_console_url_usage ; return 0 ;;
			l		) _list_roles ; return 0 ;;
			\?	) echo "Invalid option: -$OPTARG" >&2 ;;
			:		) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))
	if ! _check_exists_rolefiles ; then return 1 ; fi

	if _sts_assume_role $* ; then
		local SESSION="{\"sessionId\":\"${AWS_ACCESS_KEY_ID}\",\"sessionKey\":\"${AWS_SECRET_ACCESS_KEY}\",\"sessionToken\":\"${AWS_SESSION_TOKEN}\"}"
		local ENCODED_SESSION=$(_rawurlencode ${SESSION})
		local URL="https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=${ENCODED_SESSION}"
		local SIGNIN_TOKEN=$(curl --silent ${URL} | python -mjson.tool | grep SigninToken | awk -F\" '{print $4}')
		local CONSOLE=$(_rawurlencode "https://console.aws.amazon.com/")
		echo "https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=${CONSOLE}&SigninToken=${SIGNIN_TOKEN}"
		_popp TEMP_AWS_PARAMETERS
	else
		return 1
	fi
	# fi

}
_check_exists_rolefiles () {
	local PROFILE="${AWS_PROFILE:-$(aws configure get default.session_tool_default_profile)}"
	if [ ! -e ~/.aws/${PROFILE}_session-tool_roles.cfg ]; then
		if [ ! -e ~/.aws/${PROFILE}_roles.cfg ]; then
			_echoerr "ERROR: Neither ~/.aws/${PROFILE}_session-tool_roles.cfg nor ~/.aws/${PROFILE}_roles.cfg found, please run get_session -d or create ~/.aws/${PROFILE}_roles.cfg"
			return 1
		fi
	fi
	return 0
}
_check_exists_profile () {
	local PROFILE="${AWS_PROFILE:-$(aws configure get default.session_tool_default_profile)}"
	if test -z $PROFILE ; then
		return 1
	fi
}
_list_roles () {
	local PROFILE="${AWS_PROFILE:-$(aws configure get default.session_tool_default_profile)}"
	if _check_exists_profile ; then
		if _check_exists_rolefiles ; then
			find ~/.aws -iname ${PROFILE}_roles.cfg -or -iname ${PROFILE}_session-tool_roles.cfg 2>/dev/null | xargs cat | egrep -hv -e "^#" -e "^$" | sort -u | awk '{print $1}'
		else
			return 1
		fi
	else
		if [ ! -z "$(find ~/.aws -iname \*_roles.cfg)" ] ; then 
			echo "# INFO: No AWS_PROFILE specified (can be set by get_session, or a default profile"
			echo "        can be defined with aws configure set default.session_tool_default_profile)"
			echo "#       but some profiles were located, so showing all roles defined:"
			(find ~/.aws -iname \*_session-tool_roles.cfg ; find ~/.aws -iname \*_roles.cfg -not -iname \*_session-tool_roles.cfg) | xargs cat | egrep -hv -e "^#" -e "^$" | sort -u | awk '{print $1}'
		else
			_echoerr "ERROR: Unable to determine profile. Either specify AWS_PROFILE, do a get_session, or set a default profile with aws configure set default.session_tool_default_profile"
			return 1
		fi
	fi
}
_sts_assume_role () {
	if ! _session_ok STORED ; then
		((DBG)) && echo $STORED_AWS_PARAMETER_EXPIRATION_LOCAL
		return 1
	fi

	_pushp TEMP_AWS_PARAMETERS
	_popp STORED_AWS_PARAMETERS

	if [ -z "$1" ]; then
	  if [ -z "$AWS_ROLE_ALIAS" ]; then
			_echoerr "ERROR: Missing mandatory role alias name."
			_popp TEMP_AWS_PARAMETERS
			return 1
		fi
	else
		STORED_AWS_PARAMETER_AWS_ROLE_ALIAS="$1"
	fi


	AWS_ROLE_ALIAS=${1:-$AWS_ROLE_ALIAS}
	read tmp ROLE_ARN SESSION_NAME EXTERNAL_ID <<< $(cat ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg 2>/dev/null | egrep -m 1 "^${AWS_ROLE_ALIAS} ")

	if [ -z "$ROLE_ARN" ]; then
		_echoerr "ERROR: Missing role_arn in ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
		_popp TEMP_AWS_PARAMETERS
		return 1
	fi

	if [ -z "$SESSION_NAME" ]; then
		_echoerr "ERROR: Missing session_name in ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
		_popp TEMP_AWS_PARAMETERS
		return 1
	fi

	read tmp ASSUMED_ARN ASSUMED_ROLE tmp2 AWS_ACCESS_KEY_ID AWS_EXPIRATION AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< $( if [ -z "$EXTERNAL_ID" ]; then aws --output text sts assume-role --role-arn "${ROLE_ARN}" --role-session-name "${SESSION_NAME}" ; else aws --output text sts assume-role --role-arn ${ROLE_ARN} --role-session-name ${SESSION_NAME} --external-id ${EXTERNAL_ID} ; fi )
	
	if [ -z "$AWS_SESSION_TOKEN" ]; then
		_echoerr "ERROR: Unable to obtain session"
		_popp TEMP_AWS_PARAMETERS
		return 1
	fi

	case $OSTYPE in
		darwin*)
			AWS_EXPIRATION_S=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' $AWS_EXPIRATION +%s)
			AWS_EXPIRATION_LOCAL=$(date -j -r $AWS_EXPIRATION_S);;
		linux*)
			AWS_EXPIRATION_S=$(date -d $AWS_EXPIRATION +%s)
			AWS_EXPIRATION_LOCAL=$(date -d $AWS_EXPIRATION);;
		cygwin*)
			AWS_EXPIRATION_S=$(date -d $AWS_EXPIRATION +%s)
			AWS_EXPIRATION_LOCAL=$(date -d $AWS_EXPIRATION);;
		*)
			_echoerr "ERRROR: Unknown ostype: $OSTYPE"
			_popp TEMP_AWS_PARAMETERS
			return 1;;
		esac

	return 0
}

aws-assume-role () {
	get_session -f -p $1 $3
	assume_role $2
	get_console_url
}

# Display a set of parameters
_dumpp () {
	echo "# Parameter set:"
	for i in ${AWS_PARAMETERS} ; do
		case $1 in 
			store* | STORE* )
				printf "# %30s : %s\n" "${i}" "${STORED_AWS_PARAMETERS[$i]}" ;;
			temp* | TEMP* )
				printf "# %30s : %s\n" "${i}" "${TEMP_AWS_PARAMETERS[$i]}" ;;
			"" | current )
				printf "# %30s : %s\n" "${i}" "${!i}" ;;
		esac
	done
}

# Push the current parameters into an array
_pushp () {
	for i in ${AWS_PARAMETERS} ; do
		case $1 in 
			store* | STORE* )
					j="STORED_AWS_PARAMETER_${i}" ;;
			temp* | TEMP* )
					j="TEMPORARY_AWS_PARAMETER_${i}" ;;
			* )
				echo "WARN: you can only push to arrays STORED_AWS_PARAMETERS and TEMP_AWS_PARAMETERS"
				return 1 ;;
		esac
			export ${j}="${!i}"
	done
}

# Pop an array into the current parameters, skipping the listed parameters
_popp () {
	for i in ${AWS_PARAMETERS} ; do
		if ! [[ "$* " == *"${i} "* ]] ; then
			case $1 in 
				store* | STORE* )
					j="STORED_AWS_PARAMETER_${i}" ;;
				temp* | TEMP* )
					j="TEMPORARY_AWS_PARAMETER_${i}" ;;
				* )
					echo "WARN: you can only pop from arrays STORED_AWS_PARAMETERS and TEMP_AWS_PARAMETERS"
					return 1 ;;
			esac
			export ${i}="${!j}"
		fi
	done
}

#
# Clean up the user environment and remove every trace of an aws session
#
_aws_reset () {
	for i in ${AWS_PARAMETERS} AWS_SECURITY_TOKEN ; do
		j="STORED_AWS_PARAMETER_${i}"
		k="TEMPORARY_AWS_PARAMETER_${i}"
		unset $i $j $k
	done
}

#
# Help descriptions
#
_get_session_usage() {
	echo "Usage: get_session [-h] [-s] [-r] [-l] [-c] [-d] [-p profile] [MFA token]"
	echo ""
	echo "    MFA token    Your one time token. If not provided, and you provided"
	echo "                 the -s option, the current credentials are stored."
	echo "    -p profile   The aws credentials profile to use as an auth base."
	echo "                 The provided profile name will be cached, and be the"
	echo "                 new default for subsequent calls to get_session."
	echo "                 Current cached: $PROFILE"
	echo "                 To avoid having to enter a profile every time, you can"
	echo "                 use 'aws configure set default.session_tool_default_profile PROFILE'"
	echo "    -s           Save the resulting session to persistent storage"
	echo "                 for retrieval by other shells. You will be prompted"
	echo "                 twice for a passphrase to protect the stored credentials."
	echo "                 Note that storing with an empty passphrase does not work."
	echo "    -r           Restore previously saved state. You will be promptet for"
	echo "                 the passphrase you stated when storing the session."
	echo "    -l           List currently stored sessions including a best guess on"
	echo "                 when the session expires based on file modification time."
	echo "    -c           Resets session, removing all environment variables."
	echo "    -d           Download a list of organization-wide roles to a profile-"
	echo "                 specific file ~/.aws/[profile]_session-tool_roles.cfg"
	echo "                 These entries can be overwritten in ~/.aws/[profile]_roles.cfg"
	echo "                 Fetching is done before getting the session token, using only"
	echo "                 the permissions granted by the profile."
	echo "                 Upstream location and name of the roles list are configurable."
	echo "    -u           Uploads ~/.aws/[profile]_session-tool_roles.cfg to the"
	echo "                 configured location. Requires more priviledges than download,"
	echo "                 so is usually done after assume-role."
	echo "    -v           Verifies that the current session (not profile) is valid"
	echo "                 and not expired."
	echo "    -h           Print this usage."
	echo ""
	echo "This command will on a successful authentication return session credentials"
	echo "for the Basefarm main account. The credentials are returned in the form of"
	echo "environment variables suitable for the aws and terraform cli. The returned"
	echo "session has a duration of 12 hours."
	echo ""
	echo "At least one of -s, -r or MFA token needs to be provided."
	echo ""
	echo "Session state is stored in: ~/.aws/${PROFILE}.aes"
	echo ""
	echo "See also: get_console_url, assume_role."
}
_assume_role_usage () {
	local ROLE_ALIAS_DEFAULT=${STORED_AWS_PARAMETER_AWS_ROLE_ALIAS:-'<no cached value>'}
	echo "Usage: assume_role [-h] [-l] <role alias>"
	echo ""
	echo "    -h          Print this usage."
	echo "    -l          List available role aliases."
	echo "    role alias  The alias of the role to assume."
	echo "                The alias name will be cached, so subsequent calls to"
	echo "                assume_role or get_console_url will use the cached value."
	echo "                Current cached default: $ROLE_ALIAS_DEFAULT"
	echo ""
	echo "This command will use session credentials stored in the shell"
	echo "from previous calls to get_session The session credentials are"
	echo "then used to assume the given role."
	echo ""
	echo "This command will also set the AWS_CONSOLE_URL containing a"
	echo "pre-signed url for console access."
	echo ""
	echo "The session credentials for the assumed role will replace the"
	echo "current session in the shell environment. The only way to retrieve"
	echo "the current session after an assume_role is to have stored your"
	echo "session using get_session with the -s option and then to"
	echo "import them again using get_session -r command."
	echo ""
	echo "The assumed role credentials will only be valid for one hour,"
	echo "this is a limitation in the underlaying AWS assume_role function."
	echo ""
	echo "Roles are configured in locally in ~/.aws/${AWS_PROFILE}_roles.cfg, and"
	echo "organization-wide in ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg. The format of that file"
	echo "is as follows. Comment lines begin with #. No other type of comments"
	echo "are allowed. One line per role and each line is space separated."
	echo "The role alias is a name you choose as a shortname for the role."
	echo "external_id is optional."
	echo ""
	echo "Alias role_arn session_name external_id"
	echo ""
	echo "Example:"
	echo "# Roles for assume_role"
	echo "# Alias role_arn session_name external_id"
	echo "bf-awsopslab-admin arn:aws:iam::1234567890:role/admin bf-awsopslab-admin BF-AWSOpsLab"
	echo "foo-test arn:aws:iam::0987654321:role/admin bf-awsopslab-admin"
	echo ""
	echo "See also: get_session, get_console_url."
}
_get_console_url_usage () {
	local ROLE_ALIAS_DEFAULT=${STORED_AWS_PARAMETER_AWS_ROLE_ALIAS:-'<no cached value>'}
	echo "Usage: get_console_url [-h] [-l] <role alias>"
	echo ""
	echo "    -h          Print this usage."
	echo "    -l          List available role aliases."
	echo "    role alias  The alias of the role that will temporarily be assumed."
	echo "                The alias name will be cached, so subsequent calls to"
	echo "                assume_role or get_console_url will use the cached value."
	echo "                Current cached default: $ROLE_ALIAS_DEFAULT"
	echo ""
	echo "This command will use session credentials stored in the shell"
	echo "from previous calls to get_session The session credentials are"
	echo "then used to temporily assume the given role for the purpose of"
	echo "obtaining the console URL."
	echo ""
	echo "After this, the session credentials from previous calls to get_session"
	echo "or assume_role will be restored."
	echo "The console URL will only be valid for one hour,"
	echo "this is a limitation in the underlaying AWS assume_role function."
	echo ""
	echo "See also: get_session, assume_role. The help for assume_role has more"
	echo "information about roles definitions and files."
}

# Utility for errormessages
_echoerr() { cat <<< "$@" 1>&2; }

# Utility to urlencode a string
_rawurlencode() {
	local string="${1}"
	local strlen=${#string}
	local encoded=""

	for (( pos=0 ; pos<strlen ; pos++ )); do
		c=${string:$pos:1}
		case "$c" in
			[-_.~a-zA-Z0-9]	) o="${c}" ;;
			* 							)	printf -v o '%%%02x' "'$c"
		 esac
		 encoded+="${o}"
	done
	echo "${encoded}"
}

# Utility functino for checking if there is a current session which has not expired
_session_ok () {
	local NOW=$(date +%s)
	case $1 in 
		store* | STORE* )
				if [ -z "${STORED_AWS_PARAMETER_AWS_EXPIRATION_LOCAL}" ]; then
					_echoerr "ERROR: You do not seem to have a valid session in your environment."
					return 1
				fi
				if [ ${STORED_AWS_PARAMETER_AWS_EXPIRATION_S} -lt $NOW ]; then
					_echoerr "ERROR: Your ${STORED_AWS_PARAMETER_AWS_PROFILE} session expired at ${STORED_AWS_PARAMETER_AWS_EXPIRATION_LOCAL}."
					return 1
				fi
				;;
		temp* | TEMP* )
				if [ -z "${TEMP_AWS_PARAMETER_AWS_EXPIRATION_LOCAL}" ]; then
					_echoerr "ERROR: You do not seem to have a valid session in your environment."
					return 1
				fi
				if [ ${TEMP_AWS_PARAMETER_AWS_EXPIRATION_S} -lt $NOW ]; then
					_echoerr "ERROR: Your ${TEMP_AWS_PARAMETER_AWS_PROFILE} session expired at ${TEMP_AWS_PARAMETER_AWS_EXPIRATION_LOCAL}."
					return 1
				fi
				;;
		"" | current )
				if [ -z "${AWS_EXPIRATION_LOCAL}" ]; then
					_echoerr "ERROR: You do not seem to have a valid session in your environment."
					return 1
				fi
				if [ ${AWS_EXPIRATION_S} -lt $NOW ]; then
					_echoerr "ERROR: Your ${AWS_PROFILE} session expired at ${AWS_EXPIRATION_LOCAL}."
					return 1
				fi
				;;
		* )
			_echoerr "FATAL: Unexpected internal error trying to validate the $* session."
			return 1 ;;
	esac

	return 0
}


# Utility for initializing variables the first time this utilitie is used in a shell
# Assumes AWS_PROFILE is set
_init_aws () {

	local USER="$(aws --output text --profile $AWS_PROFILE iam get-user --query "User.Arn")"
	local SERIAL="${USER/:user/:mfa}"

	if echo "$SERIAL" | grep -q 'arn:aws:iam'; then
		export AWS_USER=$USER
		export AWS_SERIAL=$SERIAL
	else
		_echoerr "ERROR: Unable to obtain AWS user ARN using the profile: $AWS_PROFILE"
		_echoerr "DEBUG: USER=$USER"
		_echoerr "DEBUG: SERIAL=$SERIAL"
		return 1
	fi
}

_bashcompletion_sessionhandling () {
    local cur prev
    COMPREPLY=()   # Array variable storing the possible completions.
    cur=${COMP_WORDS[COMP_CWORD]}
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    if [[ ${cur} == -* ]] ; then
        opts="-h -s -r -l -c -d -p"
        COMPREPLY=( $(compgen -W "$opts" -- $cur ) )
        return 0
    fi
    if [[ ${prev} == -p ]] ; then
        profiles=`egrep '^\[profile ' ~/.aws/config | awk '{ print $2}' | sed 's/\]//'`
        COMPREPLY=( $(compgen -W "$profiles" -- $cur ) )
        return 0
    fi
    return 0
}

_bashcompletion_rolehandling ()  {
    local cur
    COMPREPLY=()   # Array variable storing the possible completions.
    cur=${COMP_WORDS[COMP_CWORD]}

    local PROFILE="${AWS_PROFILE:-$(aws configure get default.session_tool_default_profile)}"

    roles=`find ~/.aws -iname ${PROFILE}_roles.cfg -or -iname ${PROFILE}_session-tool_roles.cfg 2>/dev/null | xargs cat | egrep -hv -e "^#" -e "^$" | sort -u | awk '{print $1}'`

    COMPREPLY=( $(compgen -W "$roles" -- $cur ) )
    return 0
}

# Main loop.
# Execute _prereq to actually verify prerequisites:
_prereq
# Configure bash completetion
complete -F _bashcompletion_sessionhandling get_session
complete -F _bashcompletion_rolehandling get_console_url
complete -F _bashcompletion_rolehandling assume_role
