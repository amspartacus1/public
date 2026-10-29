#!/usr/bin/env bash
##############################################################################
# create_portfwd_user.sh
# 
# Creates an SSH user that:
# - MUST use public key auth
# - CANNOT run commands / get a shell
# - CANNOT use SCP/SFTP or transfer files
# - CAN ONLY do *local* TCP port forwarding to 127.0.0.1:8834
#
# Usage:
#   sudo ./create_portfwd_user.sh -u USERNAME -k /path/to/publickey.pub
#   sudo ./create_portfwd_user.sh -u USERNAME -K "ssh-ed25519 AAAA... comment"
#
# Creator: amspartacus1                               Last Updated: 10-29-2026
##############################################################################

set -euo pipefail

DEST_INTERFACE="127.0.0.1"
DEST_PORT=""

GROUP_NAME="pfwd_${DEST_PORT}"
FORCE_CMD="/usr/local/sbin/ssh-portforward-only"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BLOCK_BEGIN="# BEGIN managed port-forward-only (${GROUP_NAME})"
SSHD_BLOCK_END="# END managed port-forward-only (${GROUP_NAME})"

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (use sudo)."
}

usage() {
  cat >&2 <<EOF
Usage:
  $0 -u USERNAME -k /path/to/publickey.pub
  $0 -u USERNAME -K "ssh-ed25519 AAAA... comment"

Options:
  -u USERNAME   Username to create
  -k FILE       Path to an OpenSSH public key file
  -K STRING     Public key string (single line)
EOF
  exit 2
}

validate_username() {
  local u="$1"
  [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Invalid username: '$u'"
}

ensure_group() {
  if ! getent group "${GROUP_NAME}" >/dev/null; then
    groupadd --system "${GROUP_NAME}"
  fi
}

ensure_force_command() {
  if [[ ! -f "${FORCE_CMD}" ]]; then
    install -o root -g root -m 0755 /dev/stdin "${FORCE_CMD}" <<'EOF'
#!/usr/bin/env bash
# This command is forced for restricted users who try to open a shell/session.
# Port forwarding (e.g., ssh -N -L ...) does not need a session.
echo "This account is restricted to SSH local port forwarding only." >&2
echo "Example:" >&2
echo "  ssh -N -L 8834:127.0.0.1:8834 <user>@<server>" >&2
exit 1
EOF
  fi
}

ensure_sshd_block() {
  if ! grep -qF "${SSHD_BLOCK_BEGIN}" "${SSHD_CONFIG}"; then
    cp -a "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

    cat >>"${SSHD_CONFIG}" <<EOF

${SSHD_BLOCK_BEGIN}
# Users in group ${GROUP_NAME}:
# - publickey-only auth
# - no TTY / no X11 / no agent
# - ONLY local TCP forwarding
# - ONLY to ${DEST_INTERFACE}:${DEST_PORT}
# - forced command prevents shell/exec/SCP/SFTP sessions
Match Group ${GROUP_NAME}
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no

    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    PermitUserRC no

    AllowTcpForwarding local
    PermitOpen ${DEST_INTERFACE}:${DEST_PORT}

    ForceCommand ${FORCE_CMD}
${SSHD_BLOCK_END}
EOF
  fi

  # Validate sshd config before reloading
  sshd -t -f "${SSHD_CONFIG}" || die "sshd_config validation failed. Restoring from backup may be required."
}

reload_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh || systemctl reload sshd
  else
    service ssh reload || service sshd reload
  fi
}

create_user_and_key() {
  local user="$1"
  local pubkey_line="$2"

  if id "${user}" >/dev/null 2>&1; then
    die "User '${user}' already exists."
  fi

  # Create user with no shell and add to restricted group
  useradd \
    --create-home \
    --shell /usr/sbin/nologin \
    --groups "${GROUP_NAME}" \
    "${user}"

  local home_dir
  home_dir="$(getent passwd "${user}" | awk -F: '{print $6}')"
  [[ -n "${home_dir}" && -d "${home_dir}" ]] || die "Could not determine home directory for '${user}'."

  install -d -o "${user}" -g "${user}" -m 0700 "${home_dir}/.ssh"

  local ak="${home_dir}/.ssh/authorized_keys"
  touch "${ak}"
  chown "${user}:${user}" "${ak}"
  chmod 0600 "${ak}"

  # Defense-in-depth per-key restrictions:
  # - restrict: disables pty/X11/agent/user-rc (and more)
  # - port-forwarding: re-enables forwarding (since "restrict" disables it)
  # - permitopen: only allow forwarding to the web app
  #
  # Note: We intentionally do NOT add "command=" here because ForceCommand in sshd_config
  # already blocks all sessions (shell/exec/scp/sftp). Port-forward-only use (-N) does not
  # require a session.
  local key_opts
  key_opts="restrict,port-forwarding,permitopen=\"${DEST_INTERFACE}:${DEST_PORT}\""

  # Append key
  echo "${key_opts} ${pubkey_line}" >> "${ak}"
}

main() {
  need_root

  local user="" key_file="" key_string=""
  while getopts ":u:k:K:h" opt; do
    case "${opt}" in
      u) user="${OPTARG}" ;;
      k) key_file="${OPTARG}" ;;
      K) key_string="${OPTARG}" ;;
      h|*) usage ;;
    esac
  done

  [[ -n "${user}" ]] || usage
  validate_username "${user}"

  if [[ -n "${key_file}" && -n "${key_string}" ]]; then
    die "Provide either -k OR -K, not both."
  fi
  if [[ -z "${key_file}" && -z "${key_string}" ]]; then
    die "You must provide a public key via -k or -K."
  fi

  local pubkey_line=""
  if [[ -n "${key_file}" ]]; then
    [[ -r "${key_file}" ]] || die "Cannot read key file: ${key_file}"
    pubkey_line="$(tr -d '\r\n' < "${key_file}")"
  else
    pubkey_line="$(echo "${key_string}" | tr -d '\r\n')"
  fi

  # Basic sanity check: OpenSSH public key formats start with these tokens commonly.
  if [[ ! "${pubkey_line}" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
    die "That doesn't look like an OpenSSH public key line."
  fi

  ensure_group
  ensure_force_command
  ensure_sshd_block
  reload_sshd

  create_user_and_key "${user}" "${pubkey_line}"

  cat <<EOF
Created restricted user: ${user}

Client example (local forward only):
  ssh -N -L <LOCAL_PORT>:${DEST_INTERFACE}:${DEST_PORT} ${user}@<server>

This allows access to the web app via:
  http(s)://127.0.0.1:<DEST_PORT>  (on the client machine)
EOF
}

main "$@"
