#!/bin/bash
set -ueo pipefail

[ -z "${TMPDIR:-}" ] && TMPDIR=${TMPDIR:-/tmp}

vault_auth() {
  local server="$1"

  # The plugin currently supports AppRole and AWS authentication
  # These values are referenced when authenticating to the Vault server:
  #   BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD - 'approle' or 'aws'

  ##  AppRole Authentication
  #   SecretID should be stored securely on the agent when using AppRole authentication.
  #   The plugin will reference these two values for the RoleID and SecretID:
  #     BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV (default: $VAULT_SECRET_ID)
  #     BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID
  
  ##  AWS Authentication
  #   AWS auth method only requires you to pass the name of a valid Vault role in your login call, which is not
  #   sensitive information itself, so the role name to use can either be passed via BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME
  #   or will fall back to using the name of the IAM role that the instance is using. 

  ##  Kubernetes Authentication
  #   Kubernetes uses the service account token that is mounted into the pod.
  #   If auth-kubernetes-role-name is not specified, "service_buildkite" is assumed.
  #     This will often need to be customized for the naming scheme and service name used in a given organization.
  #   If auth-path is not specified, "kubernetes" is assumed.
  #     This will be typically be different if there are more than one kubernetes cluster using the same vault.

  if ! command -v vault >/dev/null 2>/dev/null; then
    echo "--- No vault binary found; installing vault v1.16.2"
    wget https://releases.hashicorp.com/vault/1.16.2/vault_1.16.2_linux_amd64.zip
    unzip vault_1.16.2_linux_amd64.zip && rm vault_1.16.2_linux_amd64.zip
    chmod +x ./vault && mv ./vault /usr/local/bin/vault
  fi

  case "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_METHOD:-}" in
    
    # AppRole authentication
    approle)
        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV:-}" ]; then
          secret_var="${VAULT_SECRET_ID?No Secret ID found}"
        else
          secret_var="${!BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_SECRET_ENV}"
        fi

        if [[ -z "${secret_var:-}" ]]; then
          echo "+++  🚨 No vault secret id found"
          exit 1
        fi
        
        # export the vault token to be used for this job - this command writes to the auth/approle/login endpoint
        # on success, vault will return the token which we export as VAULT_TOKEN for this shell
        auth_path="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_PATH:-approle}"
        if ! VAULT_TOKEN=$(vault write -field=token -address="$server" "auth/${auth_path}/login" \
        role_id="$BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID" \
        secret_id="${secret_var:-}"); then
          echo "+++🚨 Failed to get vault token"
          exit 1
        fi

        export VAULT_TOKEN

        echo "Successfully authenticated with RoleID ${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_ROLE_ID} and updated vault token"

        return "${PIPESTATUS[0]}"
      ;;

    # AWS Authentication  
    aws)
        # set the role name to use; either from the plugin configuration, or fall back to the EC2 instance role
        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME:-}" ]; then
          # Check to see if we are running on EC2
          RUNNING_ON_EC2=$(aws_platform_check)
          # get the name of the IAM role the EC2 instance is using, if any
          EC2_INSTANCE_IAM_ROLE=$( [ "$RUNNING_ON_EC2" = true ]; curl http://169.254.169.254/latest/meta-data/iam/security-credentials)
          aws_role_name="${EC2_INSTANCE_IAM_ROLE}"
        else
          aws_role_name="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_AWS_ROLE_NAME}"
        fi

        if [[ -z "${aws_role_name:-}" ]]; then
          echo "+++🚨 No EC2 instance IAM role defined; value is $aws_role_name"
          exit 1
        fi

        # export the vault token to be used for this job - this is a standard vault auth command 
        # on success, vault will return the token which we export as VAULT_TOKEN for this shell
        if ! VAULT_TOKEN=$(vault login -field=token -address="$server" -method=aws role="$aws_role_name"); then
          echo "+++🚨 Failed to get vault token"
        fi

        export VAULT_TOKEN

        echo "Successfully authenticated with IAM Role ${aws_role_name} and updated vault token"

        return "${PIPESTATUS[0]}"
      ;;

    jwt)
        echo "--- performing JWT authentication"
        if [ -z "${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV:-}" ]; then
          jwt_var="${VAULT_JWT?No JWT found}"
        else
          jwt_var="${!BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_JWT_ENV}"
        fi

        if [[ -z "${jwt_var:-}" ]]; then
          echo "+++  🚨 No JWT found."
          exit 1
        fi

        auth_path="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_PATH:-jwt}"
        if ! VAULT_TOKEN=$(vault write -address="$server" "auth/${auth_path}/login" jwt="${jwt_var:-}"); then
          echo "+++🚨 Failed to get vault token"
          exit 1
        fi

        export VAULT_TOKEN

        echo "Successfully authenticated with JWT"

        return "${PIPESTATUS[0]}"
    ;;


    kubernetes)

        jwt=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
        if [ -z "${jwt}" ]; then
          echo "+++ 🚨 No service account token found (are you running in a kubernetes pod?)"
          exit 1
        fi

        auth_path="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_PATH:-kubernetes}"
        auth_role="${BUILDKITE_PLUGIN_VAULT_SECRETS_AUTH_KUBERNETES_ROLE_NAME:-service_buildkite}"

        echo "--- Logging into Vault using Kubernetes service account token"
        echo "Logging in:"
        echo "  Vault server: ${server}"
        echo "  Vault role:   ${auth_role}"
        echo "  Auth path:    ${auth_path}"

        echo "DEBUG: vault write -address=${server} auth/${auth_path}/login role=${auth_role} jwt=...${#jwt} bytes..."
        if ! VAULT_TOKEN=$(vault write -address="${server}" "auth/${auth_path}/login" role="${auth_role}" jwt="${jwt}"); then
          echo "+++ 🚨 Failed to get vault token"
          exit 1
        fi
        echo "DEBUG: VAULT_TOKEN=...${#VAULT_TOKEN} bytes..."
        echo "DEBUG: VAULT_TOKEN=${VAULT_TOKEN:0:10}..."

        export VAULT_TOKEN

        echo "Successfully authenticated!"

        return "${PIPESTATUS[0]}"
    ;;
  esac
  
}

list_secrets() {
  local server="$1"
  local key="$2"

  local _list

  if ! _list=$(vault kv list -address="$server" -format=yaml "$key" | sed 's/^- //g'); then
    echo "unable to list secrets" >&2;
    return "${PIPESTATUS[0]}"
  fi
  local retVal=${PIPESTATUS[0]}

  for lineItem in ${_list} ; do
    echo "$key/${lineItem}"
  done

  return "$retVal"
}

secret_exists() {
  local server="$1"
  local key="$2"

  local _key_base
  _key_base="$(dirname "$key")"
  local _key_name
  _key_name="$(basename "$key")"
  local _list
  _list=$(vault kv list -address="$server" -format=yaml "$_key_base" )

  echo "${_list}" | grep "^- ${_key_name}$" >& /dev/null
  # shellcheck disable=SC2181
  if [ "$?" -ne 0 ] ; then
    return 1
  else
    return 0
  fi
}

secret_download() {
  local server="$1"
  local key="$2"
  if ! _secret=$(vault kv get -address="$server" -field=data -format=yaml "$key" | sed -r 's/: /=/; s/\"/\\"/g; s/\$/\\$/g; s/=(.*)$/=\"\1\"/g' ); then
    echo "Failed to download secrets"
    exit 1
  fi
  echo "$_secret"
}

ssh_key_download() {
  local server="$1"
  local key="$2"

  # SSH Keys must be stored as a single key inside a Vault secret named "ssh_key"
  if ! _secret="$(vault kv get -address="${server}" -field=ssh_key "${key}")"; then
    echo "Failed to download secrets"
    exit 1
  fi
  echo "$_secret"
}

add_ssh_private_key_to_agent() {
  local ssh_key="$1"

  if [[ -z "${SSH_AGENT_PID:-}" ]] ; then
    echo "Starting an ephemeral ssh-agent" >&2;
    eval "$(ssh-agent -s)"
  fi

  echo "Loading ssh-key into ssh-agent (pid ${SSH_AGENT_PID:-})" >&2;

  echo "$ssh_key" | env SSH_ASKPASS="/bin/false" ssh-add -
}

grep_secrets() {
  grep -E 'private_ssh_key|id_rsa_github|env|environment|git-credentials$' "$@"
}


aws_platform_check() {
    if [ -f /sys/hypervisor/uuid ]; then
      if [ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]; then
        return 0
      else
        return 1
      fi

    elif [ -r /sys/devices/virtual/dmi/id/product_uuid ]; then
      if [ "$(head -c 3 /sys/devices/virtual/dmi/id/product_uuid)" == "EC2" ]; then
        return 0
      else
        return 1
      fi
    fi
}
