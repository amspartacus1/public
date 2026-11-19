#!/usr/bin/env bash
#
# Create a user that is restricted to uploading files over SSH (SFTP/SCP-only).
# Usage: ./create_scp_upload_user.sh <username> [jail_base_dir]
#
# - user is chrooted and can only use internal-sftp (no shell, no port forwarding)
# - default jail_base_dir: /sftp-jail
#
# Run as root.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[-] This script must be run as root." >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <username> [jail_base_dir]" >&2
  exit 1
fi

USERNAME="$1"
JAIL_BASE="${2:-/sftp-jail}"

SSHD_CONFIG="/etc/ssh/sshd_config"

# 1. Create the chroot directory structure
JAIL_DIR="${JAIL_BASE}/${USERNAME}"
UPLOAD_DIR="${JAIL_DIR}/upload"

echo "[*] Creating chroot directories at: ${JAIL_DIR}"
mkdir -p "${UPLOAD_DIR}"

# Chroot directory *must* be owned by root and not writable by the user.
chown root:root "${JAIL_DIR}"
chmod 755 "${JAIL_DIR}"

# Upload directory can be owned by the restricted user.
# We'll create the user first if they don't exist.
if id "${USERNAME}" >/dev/null 2>&1; then
  echo "[*] User ${USERNAME} already exists, updating shell and home directory..."
  usermod -d "${JAIL_DIR}" -s /usr/sbin/nologin "${USERNAME}"
else
  echo "[*] Creating user ${USERNAME}..."
  useradd \
    -d "${JAIL_DIR}" \
    -s /usr/sbin/nologin \
    -M \
    "${USERNAME}"

  echo "[*] Set a password for ${USERNAME}:"
  passwd "${USERNAME}"
fi

chown "${USERNAME}:${USERNAME}" "${UPLOAD_DIR}"
chmod 700 "${UPLOAD_DIR}"

# 2. Ensure internal-sftp is enabled
if ! grep -qE '^\s*Subsystem\s+sftp\s+internal-sftp' "${SSHD_CONFIG}"; then
  echo "[*] Enabling internal-sftp in ${SSHD_CONFIG}..."
  # Comment out existing sftp subsystem lines and add internal-sftp
  sed -i 's/^\s*Subsystem\s\+sftp\s\+.*/# &/' "${SSHD_CONFIG}"
  echo 'Subsystem sftp internal-sftp' >> "${SSHD_CONFIG}"
fi

# 3. Append a Match block for this user
MATCH_BLOCK=$(cat <<EOF

# Restricted upload-only SSH user: ${USERNAME}
Match User ${USERNAME}
    ChrootDirectory ${JAIL_DIR}
    ForceCommand internal-sftp -d /upload
    X11Forwarding no
    AllowTcpForwarding no
    PermitTunnel no
    GatewayPorts no
    PasswordAuthentication yes
EOF
)

if grep -q "Restricted upload-only SSH user: ${USERNAME}" "${SSHD_CONFIG}"; then
  echo "[*] Match block for ${USERNAME} already present in ${SSHD_CONFIG}, skipping append."
else
  echo "[*] Adding Match block for ${USERNAME} to ${SSHD_CONFIG}..."
  printf "%s\n" "${MATCH_BLOCK}" >> "${SSHD_CONFIG}"
fi

# 4. Reload sshd to apply changes
echo "[*] Reloading sshd..."
if systemctl reload sshd 2>/dev/null; then
  echo "[+] Reloaded sshd via systemctl sshd"
elif systemctl reload ssh 2>/dev/null; then
  echo "[+] Reloaded ssh via systemctl ssh"
elif service sshd reload 2>/dev/null; then
  echo "[+] Reloaded sshd via service sshd reload"
elif service ssh reload 2>/dev/null; then
  echo "[+] Reloaded ssh via service ssh reload"
else
  echo "[!] Could not automatically reload sshd. Please reload it manually." >&2
fi

cat <<INFO

[+] User ${USERNAME} created/updated.

Connection instructions (from client):

  # Upload a file using scp (modern OpenSSH scp may speak SFTP under the hood):
  scp somefile ${USERNAME}@yourserver:/upload/

  # Or use sftp explicitly:
  sftp ${USERNAME}@yourserver
  sftp> put somefile /upload/

The user:
  - is chrooted to ${JAIL_DIR}
  - can only access the /upload directory inside the jail
  - cannot get an interactive shell
  - cannot port forward or run arbitrary commands

INFO
