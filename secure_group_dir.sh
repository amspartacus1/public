#!/usr/bin/env bash
# secure_group_dir.sh
# Create a /srv directory writable by a given group, locked down from others.
# New files/dirs inside inherit the same permissions.

set -euo pipefail

usage() {
    cat <<EOF
Usage: sudo $0 <group> <name-or-path-under-/srv> [--recursive|-r]

Examples:
  sudo $0 analysts reports          # creates /srv/reports
  sudo $0 analysts /srv/data/share  # uses explicit path under /srv
  sudo $0 analysts reports -r       # also fixes any existing contents

Notes:
  - Requires the 'acl' package (setfacl).
  - Root privileges are required.
EOF
    exit 1
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

# --- Preconditions -----------------------------------------------------------
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (use sudo)."

command -v setfacl >/dev/null 2>&1 || die "setfacl not found. Install the 'acl' package."

GROUP="${1:-}"
TARGET="${2:-}"
RECURSE="${3:-}"
[[ -n "${GROUP}" && -n "${TARGET}" ]] || usage

getent group "${GROUP}" >/dev/null 2>&1 || die "Group '${GROUP}' does not exist."

# Build absolute path and enforce /srv prefix
if [[ "${TARGET}" = /* ]]; then
    DIR="${TARGET}"
else
    DIR="/srv/${TARGET}"
fi
[[ "${DIR}" == /srv/* ]] || die "Target must be under /srv (got: ${DIR})"

# --- Create / configure directory -------------------------------------------
mkdir -p "${DIR}"

# Make root the owner and the target group the group-owner
chown root:"${GROUP}" "${DIR}"

# chmod 2770:
#  - rwx for owner and group
#  - no permissions for others
#  - setgid bit so new items inherit the directory's group
chmod 2770 "${DIR}"

# Clear any pre-existing ACLs on the top directory
setfacl -b "${DIR}" || true

# Set ACLs:
#  - Current dir: group has rwx; others have no access.
#  - Default ACLs: future files/dirs inherit group rw (and X for dirs), others none.
#    Use 'X' so regular files will not get  x unless explicitly created executable.
setfacl -m u::rwx,g::rwx,o::---,mask::rwx "${DIR}"
setfacl -d -m u::rwx,g::rwX,o::---,mask::rwX "${DIR}"

# --- Optional: make existing contents compliant -----------------------------
if [[ "${RECURSE:-}" == "--recursive" || "${RECURSE:-}" == "-r" ]]; then
    # Ensure all existing content has the right group and perms
    chgrp -R "${GROUP}" "${DIR}"
    chmod -R g rwX,o-rwx "${DIR}"
    # Ensure setgid bit on all subdirectories
    find "${DIR}" -type d -exec chmod g s {}

    # Reset any stray ACLs, then reapply consistent ACLs recursively
    setfacl -R -b "${DIR}" || true
    setfacl -R -m u::rwX,g::rwX,o::---,mask::rwX "${DIR}"
    setfacl -R -d -m u::rwx,g::rwX,o::---,mask::rwX "${DIR}"
fi

echo "✅ Secure group directory ready at: ${DIR}"
echo "   (owner: root, group: ${GROUP}, perms: 2770, default ACLs applied)"
echo
echo "Effective ACL summary:"
getfacl -p "${DIR}" | sed -n '1,20p'
