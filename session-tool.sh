#!/bin/bash
VERSION=1.2.1
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

# Please refer to the

# Verify all prerequisites
_prereq () {
  type curl >/dev/null 2>&1 || echo >&2 "ERROR: curl is not found. session_tools will not work."
  case $OSTYPE in
    darwin*) _OPENSSL="/usr/bin/openssl";;
    linux*)  _OPENSSL="openssl";;
    cygwin*) _OPENSSL="openssl";;
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
	type wget >/dev/null 2>&1 || echo >&2 "ERROR: wget is not found. session_tools will not work."
  [[ `ps -fp $$ | grep $$` =~ "bash" ]] || echo >&2 "ERROR: SHELL is not bash. session_tools will not work."

	PUBVERSION="$(wget -qO- "${PUBURL}" | grep ^VERSION= | cut -d '=' -f 2)"
	test "${PUBVERSION}" = "${VERSION}" || echo >&2 "WARN: Your version is outdated! You have ${VERSION}, the latest is ${PUBVERSION}"
}

# Utility for errormessages
_echoerr() { cat <<< "$@" 1>&2; }

#
# Utility to urlencode a string
#
_rawurlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
         [-_.~a-zA-Z0-9] ) o="${c}" ;;
         * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"
}

_session_not_ok () {
  local NOW=$(date +%s)
  if [ -z "$AWS_EXPIRATION_S_STORED" ]; then
    _echoerr "ERROR: You do not seem to have a valid session in your environment."
    return 0
  fi
  if [ $AWS_EXPIRATION_S_STORED -lt $NOW ]; then
    _echoerr "ERROR: Your $AWS_PROFILE_STORED session expired at $AWS_EXPIRATION_LOCAL_STORED."
    return 0
  fi

  return 1
}


#
# Clean up the user environment and remove every trace of an aws session
#
_aws_reset () {
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
  AWS_ROLE_NAME AWS_ROLE_EXPIRATION AWS_SECURITY_TOKEN AWS_USER \
	AWS_CONSOLE_URL AWS_CONSOLE_URL_EXPIRATION AWS_CONSOLE_URL_EXPIRATION_LOCAL AWS_EXPIRATION AWS_CONSOLE_URL_EXPIRATION_S \
	AWS_EXPIRATION_LOCAL AWS_EXPIRATION_S AWS_PROFILE AWS_ROLE_ALIAS AWS_SERIAL \
	AWS_USER_STORED AWS_SERIAL_STORED AWS_PROFILE_STORED AWS_SECRET_ACCESS_KEY_STORED \
	AWS_SESSION_TOKEN_STORED AWS_ACCESS_KEY_ID_STORED AWS_EXPIRATION_STORED AWS_EXPIRATION_S_STORED AWS_EXPIRATION_LOCAL_STORED
}

# Local function for looking up stuff the first time this utilitie is used in a shell
# Assume AWS_PROFILE is set
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

_get_session_usage() {
	echo "Usage: get_session [-h] [-s] [-r] [-l] [-c] [-d] [-p profile] [MFA token]"
	echo ""
	echo "    MFA token    Your one time token. If not provided, and you provided"
	echo "                 the -s option, the current credentials are stored."
	echo "    -p profile   The aws credentials profile to use as an auth base."
	echo "                 The provided profile name will be cached, and be the"
	echo "                 new default for subsequent calls to get_session."
	echo "                 Current default: $PROFILE"
	echo "    -s           Save the resulting session to persistent storage"
	echo "                 for retrieval by other shells. You will be prompted"
	echo "                 twice for a passphrase to protect the stored credentials."
	echo "                 Note that storing with an empty passphrase does not work."
	echo "    -r           Restore previously saved state. You will be promptet for"
	echo "                 the passphrase you stated when storing the session."
	echo "    -l           List currently stored sessions including a best guess on"
	echo "                 when the session expires based on file modification time."
	echo "    -c           Resets session."
	echo "    -d           Download a list of organization-wide roles to a profile-"
	echo "                 specific file ~/.aws/[profile]_session-tool_roles.cfg"
	echo "                 These entries can be overwritten in ~/.aws/[profile]_roles.cfg"
	echo "                 Fetching is done before getting the session token, using only"
	echo "                 the permissions granted by the profile."
	echo "                 Upstream location and name of the roles list are configureable."
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

get_session() {
	
	local OPTIND ; local PROFILE="${AWS_PROFILE}" ; local STORE=false; local RESTORE=false; local DOWNLOAD=false; local VERIFY=false; local UPLOAD=false

	# extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":cdhlp:rsuv" opt ; do
		case "$opt" in
			h  ) _get_session_usage ; return 0 ;;
			c  ) _aws_reset ; return 0 ;;
			l  )
				local now=$(date +%s)
				for f in `ls ~/.aws/*.aes`; do
					local expiry_s=$(expr $(date -r $f '+%s') + 43200 )
					case $OSTYPE in
						darwin*) local expiry_l=$(date -r $expiry_s '+%H:%M:%S %Y-%m-%d');;
						linux*) local expiry_l=$(date -d @${expiry_s} '+%H:%M:%S %Y-%m-%d');;
						cygwin*) local expiry_l=$(date -d @${expiry_s} '+%H:%M:%S %Y-%m-%d');;
						*) _echoerr "ERROR: Unknown ostype: $OSTYPE" ; return 1 ;;
					esac
					local profile=$(basename $f .aes)
					if [ $expiry_s -lt $now ]; then
						echo "$profile $expiry_l (EXPIRED)"
					else
						echo "$profile $expiry_l"
					fi
				done
				return 0 ;;
			p  ) PROFILE=$OPTARG ;;
			s  ) STORE=true ;;
			r  ) RESTORE=true ;;
			d  ) DOWNLOAD=true ;;
			u  ) UPLOAD=true ;;
			v  ) VERIFY=true ;;
			\? ) echo "Invalid option: -$OPTARG" >&2 ;;
			:  ) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))
  if test -z ${PROFILE} ; then
	  if aws configure list | grep -q '<not set>' ; then
		  _echoerr "ERROR: No profile specified and no default profile configured."
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
			if aws s3 cp --quiet "s3://${ROLEBUCKET}/${ROLESFILE}" ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg ; then
				return 0
			else
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
	# Upload like this: aws s3 cp --acl private /tmp/bf-roles.cfg s3://bf-aws-tools-session-tool/

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
		local TEMP_AWS_USER="${AWS_USER}"
		local TEMP_AWS_SERIAL="${AWS_SERIAL}"
		local TEMP_AWS_PROFILE="${AWS_PROFILE}"
		local TEMP_AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}"
		local TEMP_AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}"
		local TEMP_AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"
		local TEMP_AWS_EXPIRATION="${AWS_EXPIRATION}"
		local TEMP_AWS_EXPIRATION_S="${AWS_EXPIRATION_S}"
		local TEMP_AWS_EXPIRATION_LOCAL="${AWS_EXPIRATION_LOCAL}"
		AWS_USER="${AWS_USER_STORED}"
		AWS_SERIAL="${AWS_SERIAL_STORED}"
		AWS_PROFILE="${AWS_PROFILE_STORED}"
		AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY_STORED}"
		AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN_STORED}"
		AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID_STORED}"
		AWS_EXPIRATION="${AWS_EXPIRATION_STORED}"
		AWS_EXPIRATION_S="${AWS_EXPIRATION_S_STORED}"
		AWS_EXPIRATION_LOCAL="${AWS_EXPIRATION_LOCAL_STORED}"
		local response="$(aws sts get-caller-identity 2>&1)"
		AWS_USER="${TEMP_AWS_USER}"
		AWS_SERIAL="${TEMP_AWS_SERIAL}"
		AWS_PROFILE="${TEMP_AWS_PROFILE}"
		AWS_SECRET_ACCESS_KEY="${TEMP_AWS_SECRET_ACCESS_KEY}"
		AWS_SESSION_TOKEN="${TEMP_AWS_SESSION_TOKEN}"
		AWS_ACCESS_KEY_ID="${TEMP_AWS_ACCESS_KEY_ID}"
		AWS_EXPIRATION="${TEMP_AWS_EXPIRATION}"
		AWS_EXPIRATION_S="$TEMP_AWS_EXPIRATION_S}"
		AWS_EXPIRATION_LOCAL="${TEMP_AWS_EXPIRATION_LOCAL}"

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

		eval "$CREDENTIALS"
		if _session_not_ok; then
			return $?
		fi

		local NOW=$(date +%s)
		local EXP_HOUR=$(($AWS_EXPIRATION_S + 3600))

		if [ $EXP_HOUR -lt $NOW ]; then
			echo "WARNING: Your $AWS_PROFILE stored session will expire at $AWS_EXPIRATION_LOCAL."
		fi

		local CREDS=$(echo "$CREDENTIALS" | sed 's/^/export /')
		eval "$CREDS"
		export AWS_USER AWS_SERIAL AWS_PROFILE
		export AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID
		export AWS_EXPIRATION AWS_EXPIRATION_S AWS_EXPIRATION_LOCAL
		export AWS_USER_STORED AWS_SERIAL_STORED AWS_PROFILE_STORED
		export AWS_SECRET_ACCESS_KEY_STORED AWS_SESSION_TOKEN_STORED AWS_ACCESS_KEY_ID_STORED
		export AWS_EXPIRATION_STORED AWS_EXPIRATION_S_STORED AWS_EXPIRATION_LOCAL_STORED
		return 0
	fi

	# Making new session, with optional MFA
	if [ -z "$AWS_USER" ]; then
		_init_aws
	fi
	if [ "${AWS_PROFILE}" != "${AWS_PROFILE_STORED}" ] ; then
		_init_aws
	fi

	# If there is an MFA, then it should be numeric and used for the sts get-session-token call
	if [ -n "$1" ]; then
		# Verify the MFA token code, AWS currently only support 6 numbers
		local re='^[0-9][0-9][0-9][0-9][0-9][0-9]$'
		if ! [[ "$1" =~ $re ]]; then
			_echoerr "ERROR: MFA token code can only consist of 6 numbers."
			return 1
		fi

	  local MFA=$1
	  local JSON=$(aws --output json --profile $AWS_PROFILE sts get-session-token --serial-number=$AWS_SERIAL --token-code $MFA )

	else
		local JSON=$(aws --output json --profile $AWS_PROFILE sts get-session-token )
		# When not using MFA, it is usually by mistake so we issue a warninh
		_echoerr "# Warning: you did not input an MFA token. Proceed at your own risk."
	fi

	# MFA or not, there should be a JSON returned
	if [ -z "$JSON" ]; then
		_echoerr "ERROR: Unable to obtain session"
		return 1
	fi

	local JSON_NORM=$(echo $JSON | python -mjson.tool)
	local SECRET_ACCESS_KEY=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SecretAccessKey") print $4}')
	local SESSION_TOKEN=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SessionToken") print $4}')
	local ACCESS_KEY_ID=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "AccessKeyId") print $4}')
	local EXPIRATION=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "Expiration") print $4}')

	if [ -z "$SESSION_TOKEN" ]; then
		_echoerr "ERROR: Unable to obtain session"
		return 1
	fi

	case $OSTYPE in
		darwin*)
			local EXPIRATION_S=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' $EXPIRATION  +%s)
			local EXPIRATION_LOCAL=$(date -j -r $EXPIRATION_S);;
		linux*)
			local EXPIRATION_S=$(date -d $EXPIRATION  +%s)
			local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
		cygwin*)
			local EXPIRATION_S=$(date -d $EXPIRATION  +%s)
			local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
		*)
		_echoerr "ERROR: Unknown ostype: $OSTYPE"
		return 1;;
	esac

	export AWS_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
	export AWS_SESSION_TOKEN=$SESSION_TOKEN
	export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
	export AWS_EXPIRATION=$EXPIRATION
	export AWS_EXPIRATION_S=$EXPIRATION_S
	export AWS_EXPIRATION_LOCAL=$EXPIRATION_LOCAL
	export AWS_USER_STORED=$AWS_USER
	export AWS_SERIAL_STORED=$AWS_SERIAL
	export AWS_PROFILE_STORED=$AWS_PROFILE
	export AWS_SECRET_ACCESS_KEY_STORED=$SECRET_ACCESS_KEY
	export AWS_SESSION_TOKEN_STORED=$SESSION_TOKEN
	export AWS_ACCESS_KEY_ID_STORED=$ACCESS_KEY_ID
	export AWS_EXPIRATION_STORED=$EXPIRATION
	export AWS_EXPIRATION_S_STORED=$EXPIRATION_S
	export AWS_EXPIRATION_LOCAL_STORED=$EXPIRATION_LOCAL

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
AWS_USER_STORED='$AWS_USER'
AWS_SERIAL_STORED='$AWS_SERIAL'
AWS_PROFILE_STORED='$AWS_PROFILE'
AWS_SECRET_ACCESS_KEY_STORED='$AWS_SECRET_ACCESS_KEY'
AWS_SESSION_TOKEN_STORED='$AWS_SESSION_TOKEN'
AWS_ACCESS_KEY_ID_STORED='$AWS_ACCESS_KEY_ID'
AWS_EXPIRATION_STORED='$AWS_EXPIRATION'
AWS_EXPIRATION_S_STORED='$AWS_EXPIRATION_S'
AWS_EXPIRATION_LOCAL_STORED='$AWS_EXPIRATION_LOCAL'
EOF
	fi
}

get_console_url () {
	local OPTIND

  if [ ! -e ~/.aws/${AWS_PROFILE}_roles.cfg ]; then
	  if [ ! -e ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg ]; then
  	  _echoerr "ERROR: Neither ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg nor ~/.aws/${AWS_PROFILE}_roles.cfg found, please run get_session -d"
	    return 1
		fi
	fi

    # extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":hl" opt ; do
		case "$opt" in
			h )
				local ROLE_ALIAS_DEFAULT=${AWS_ROLE_ALIAS:-'<no cached value>'}
				echo "Usage: get_console_url [-h] [-l] [<role alias>]"
				echo ""
				echo "    -h          Print this usage."
				echo "    -l          List available role aliases."
				echo "    role alias  The alias of the role to assume."
				echo "                The alias name will be cached, so subsequent"
				echo "                calls to get_console_url will use the cached value."
				echo "                Current cached default: $ROLE_ALIAS_DEFAULT"
				echo ""
				echo "This command will use session credentials stored in the shell"
				echo "from previous calls to get_session. The session credentials are"
				echo "then used to assume the given role and finaly to create"
				echo "a pre-signed URL for console access."
				echo ""
				echo "Roles are configured locally in ~/.aws/${AWS_PROFILE}_roles.cfg, and"
				echo "organization-wide in ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
				echo ""
				echo "See also: get_session, assume_role."
				return 0 ;;
			l ) egrep -hv -e "^#" -e "^$" ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg | awk '{print $1}' | sort -u
				return 0 ;;
			\? ) echo "Invalid option: -$OPTARG" >&2 ;;
			:  ) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))

  if _session_not_ok; then
    return $?
  fi

  if [ -z "$1" ]; then
    if [ -z "$AWS_ROLE_ALIAS" ];  then
	    _echoerr "ERROR: Missing mandatory role alias name."
	    return 1
    fi
  fi

  ROLE_ALIAS=${1:-$AWS_ROLE_ALIAS}
  local LINE=$(cat ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg 2>/dev/null | egrep -m 1 "^${ROLE_ALIAS} ")
  local ROLE_ARN=$(echo $LINE | awk '{print $2}')
  local SESSION_NAME=$(echo $LINE | awk '{print $3}')
  local EXTERNAL_ID=$(echo $LINE | awk '{print $4}')

  if [ -z "$ROLE_ARN" ]; then
    _echoerr "ERROR: Missing role_arn in ~/.aws/${AWS_PROFILE}_roles.cfg and ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
	  return 1
  fi

  if [ -z "$SESSION_NAME" ]; then
    _echoerr "ERROR: Missing session_name in ~/.aws/${AWS_PROFILE}_roles.cfg and ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
    return 1
  fi

  local AWS_ROLE_ALIAS=$ROLE_ALIAS
	local AWS_USER="${AWS_USER_STORED}"
	local AWS_SERIAL="${AWS_SERIAL_STORED}"
	local AWS_PROFILE="${AWS_PROFILE_STORED}"
	local AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY_STORED}"
	local AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN_STORED}"
	local AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID_STORED}"
	local AWS_EXPIRATION="${AWS_EXPIRATION_STORED}"
	local AWS_EXPIRATION_S="${AWS_EXPIRATION_S_STORED}"
	local AWS_EXPIRATION_LOCAL="${AWS_EXPIRATION_LOCAL_STORED}"

  if [ -z "$EXTERNAL_ID" ]; then
    local JSON=$(aws --output json sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME")
  else
    local JSON=$(aws --output json sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --external-id "$EXTERNAL_ID")
  fi

  if [ -z "$JSON" ]; then
    _echoerr "ERROR: Unable to obtain session"
    return 1
  fi

  local JSON_NORM=$(echo $JSON | python -mjson.tool)
  local SECRET_ACCESS_KEY=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SecretAccessKey") print $4}')
  local SESSION_TOKEN=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SessionToken") print $4}')
  local ACCESS_KEY_ID=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "AccessKeyId") print $4}')
  local EXPIRATION=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "Expiration") print $4}')
  if [ -z "$SESSION_TOKEN" ]; then
    _echoerr "ERROR: Unable to obtain session"
    return 1
  fi

  local SESSION="{\"sessionId\":\"${ACCESS_KEY_ID}\",\"sessionKey\":\"${SECRET_ACCESS_KEY}\",\"sessionToken\":\"${SESSION_TOKEN}\"}"
  local ENCODED_SESSION=$(_rawurlencode ${SESSION})
  local URL="https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=${ENCODED_SESSION}"
  local SIGNIN_TOKEN=$(curl --silent ${URL} | python -mjson.tool | grep SigninToken | awk -F\" '{print $4}')
  local CONSOLE=$(_rawurlencode "https://console.aws.amazon.com/")
  export AWS_CONSOLE_URL="https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=${CONSOLE}&SigninToken=${SIGNIN_TOKEN}"

  case $OSTYPE in
	darwin*)
	  local EXPIRATION_S=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' $EXPIRATION +%s)
	  local EXPIRATION_LOCAL=$(date -j -r $EXPIRATION_S);;
	linux*)
	  local EXPIRATION_S=$(date -d $EXPIRATION +%s)
	  local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
	cygwin*)
		local EXPIRATION_S=$(date -d $EXPIRATION +%s)
	  local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
	*)
    _echoerr "ERRROR: Unknown ostype: $OSTYPE"
    return 1;;
  esac

  export AWS_CONSOLE_URL_EXPIRATION=$EXPIRATION
  export AWS_CONSOLE_URL_EXPIRATION_S=$EXPIRATION_S
  export AWS_CONSOLE_URL_EXPIRATION_LOCAL=$EXPIRATION_LOCAL
  echo $AWS_CONSOLE_URL
}

assume_role () {
  local OPTIND
  if [ ! -e ~/.aws/${AWS_PROFILE}_roles.cfg ]; then
		touch ~/.aws/${AWS_PROFILE}_roles.cfg
		_echoerr "INFO: No ~/.aws/${AWS_PROFILE}_roles.cfg, initializing empty file"
  fi
  if [ ! -e ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg ]; then
		_echoerr "ERROR: ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg, please run get_session -d"
		return 1
	fi

  # extract options and their arguments into variables. Help and List are dealt with directly
	while getopts ":hl" opt ; do
		case "$opt" in
			h )
				local ROLE_ALIAS_DEFAULT=${AWS_ROLE_ALIAS:-'<no cached value>'}
				echo "Usage: assume_role [-h] [-l] <role alias>"
				echo ""
				echo "    -h          Print this usage."
				echo "    -l          List available role aliases."
				echo "    role alias  The alias of the role to assume."
				echo "                The alias name will be cached, so subsequent"
				echo "                calls to get_console_url will use the cached value."
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
				return 0 ;;
			l ) egrep -hv -e "^#" -e "^$" ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg | awk '{print $1}' | sort -u
				return 0 ;;
			\? ) echo "Invalid option: -$OPTARG" >&2 ;;
			:  ) echo "Option -$OPTARG requires an argument." >&2 ; exit 1 ;;
		esac
	done
	shift $((OPTIND-1))

  if _session_not_ok; then
    return $?
  fi

  if [ -z "$1" ]; then
	   if [ -z "$AWS_ROLE_ALIAS" ];  then
       _echoerr "ERROR: Missing mandatory role alias name."
       return 1
     fi
  fi

  ROLE_ALIAS=${1:-$AWS_ROLE_ALIAS}
  local LINE=$(cat ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg 2>/dev/null | egrep -m 1 "^${ROLE_ALIAS} ")
  local ROLE_ARN=$(echo $LINE | awk '{print $2}')
  local SESSION_NAME=$(echo $LINE | awk '{print $3}')
  local EXTERNAL_ID=$(echo $LINE | awk '{print $4}')

  if [ -z "$ROLE_ARN" ]; then
    _echoerr "ERROR: Missing role_arn in ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
    return 1
  fi

  if [ -z "$SESSION_NAME" ]; then
    _echoerr "ERROR: Missing session_name in ~/.aws/${AWS_PROFILE}_roles.cfg ~/.aws/${AWS_PROFILE}_session-tool_roles.cfg"
    return 1
  fi

  AWS_ROLE_ALIAS="${ROLE_ALIAS}"
	local TEMP_AWS_USER="${AWS_USER}"
	local TEMP_AWS_SERIAL="${AWS_SERIAL}"
	local TEMP_AWS_PROFILE="${AWS_PROFILE}"
	local TEMP_AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}"
	local TEMP_AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}"
	local TEMP_AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"
	local TEMP_AWS_EXPIRATION="${AWS_EXPIRATION}"
	local TEMP_AWS_EXPIRATION_S="${AWS_EXPIRATION_S}"
	local TEMP_AWS_EXPIRATION_LOCAL="${AWS_EXPIRATION_LOCAL}"

	AWS_USER="${AWS_USER_STORED}"
	AWS_SERIAL="${AWS_SERIAL_STORED}"
	AWS_PROFILE="${AWS_PROFILE_STORED}"
	AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY_STORED}"
	AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN_STORED}"
	AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID_STORED}"
	AWS_EXPIRATION="${AWS_EXPIRATION_STORED}"
	AWS_EXPIRATION_S="${AWS_EXPIRATION_S_STORED}"
	AWS_EXPIRATION_LOCAL="${AWS_EXPIRATION_LOCAL_STORED}"

  if [ -z "$EXTERNAL_ID" ]; then
		local JSON=$(aws --output json sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME")
  else
		local JSON=$(aws --output json sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --external-id "$EXTERNAL_ID")
  fi

  if [ -z "$JSON" ]; then
		_echoerr "ERROR: Unable to obtain session"
		AWS_USER="${TEMP_AWS_USER}"
		AWS_SERIAL="${TEMP_AWS_SERIAL}"
		AWS_PROFILE="${TEMP_AWS_PROFILE}"
		AWS_SECRET_ACCESS_KEY="${TEMP_AWS_SECRET_ACCESS_KEY}"
		AWS_SESSION_TOKEN="${TEMP_AWS_SESSION_TOKEN}"
		AWS_ACCESS_KEY_ID="${TEMP_AWS_ACCESS_KEY_ID}"
		AWS_EXPIRATION="${TEMP_AWS_EXPIRATION}"
		AWS_EXPIRATION_S="$TEMP_AWS_EXPIRATION_S}"
		AWS_EXPIRATION_LOCAL="${TEMP_AWS_EXPIRATION_LOCAL}"
    return 1
  fi

  local JSON_NORM=$(echo $JSON | python -mjson.tool)
  local SECRET_ACCESS_KEY=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SecretAccessKey") print $4}')
  local SESSION_TOKEN=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "SessionToken") print $4}')
  local ACCESS_KEY_ID=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "AccessKeyId") print $4}')
  local EXPIRATION=$(echo "$JSON_NORM" | awk -F\" '{if ($2 == "Expiration") print $4}')

  if [ -z "$SESSION_TOKEN" ]; then
    _echoerr "ERROR: Unable to obtain session"
    AWS_USER="${TEMP_AWS_USER}"
    AWS_SERIAL="${TEMP_AWS_SERIAL}"
    AWS_PROFILE="${TEMP_AWS_PROFILE}"
    AWS_SECRET_ACCESS_KEY="${TEMP_AWS_SECRET_ACCESS_KEY}"
    AWS_SESSION_TOKEN="${TEMP_AWS_SESSION_TOKEN}"
    AWS_ACCESS_KEY_ID="${TEMP_AWS_ACCESS_KEY_ID}"
    AWS_EXPIRATION="${TEMP_AWS_EXPIRATION}"
    AWS_EXPIRATION_S="$TEMP_AWS_EXPIRATION_S}"
    AWS_EXPIRATION_LOCAL="${TEMP_AWS_EXPIRATION_LOCAL}"
    return 1
  fi

  local SESSION="{\"sessionId\":\"${ACCESS_KEY_ID}\",\"sessionKey\":\"${SECRET_ACCESS_KEY}\",\"sessionToken\":\"${SESSION_TOKEN}\"}"
  local ENCODED_SESSION=$(_rawurlencode ${SESSION})
  local URL="https://signin.aws.amazon.com/federation?Action=getSigninToken&Session=${ENCODED_SESSION}"
  local SIGNIN_TOKEN=$(curl --silent ${URL} | python -mjson.tool | grep SigninToken | awk -F\" '{print $4}')
  local CONSOLE=$(_rawurlencode "https://console.aws.amazon.com/")
  export AWS_CONSOLE_URL="https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=${CONSOLE}&SigninToken=${SIGNIN_TOKEN}"

  case $OSTYPE in
	darwin*)
    local EXPIRATION_S=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' $EXPIRATION +%s)
    local EXPIRATION_LOCAL=$(date -j -r $EXPIRATION_S);;
	linux*)
	  local EXPIRATION_S=$(date -d $EXPIRATION +%s)
	  local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
	cygwin*)
	  local EXPIRATION_S=$(date -d $EXPIRATION +%s)
	  local EXPIRATION_LOCAL=$(date -d $EXPIRATION);;
	*)
	  _echoerr "ERRROR: Unknown ostype: $OSTYPE"
	  return 1;;
  esac

  export AWS_CONSOLE_URL_EXPIRATION=$EXPIRATION
  export AWS_CONSOLE_URL_EXPIRATION_S=$EXPIRATION_S
  export AWS_CONSOLE_URL_EXPIRATION_LOCAL=$EXPIRATION_LOCAL
  export AWS_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
  export AWS_SESSION_TOKEN=$SESSION_TOKEN
  export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
  export AWS_EXPIRATION=$EXPIRATION
  export AWS_EXPIRATION_S=$EXPIRATION_S
  export AWS_EXPIRATION_LOCAL=$EXPIRATION_LOCAL
}

aws-assume-role () {
	get_session -f -p $1 $3
	assume_role $2
	get_console_url
}


# Execute _prereq to actually verify:
_prereq
