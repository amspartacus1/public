#!/usr/bin/env bash
# blacklist.sh
# Block outbound traffic to IPs/ranges using ipset+iptables (REJECT),
# with dependency checks, snapshot/restore, clear/flush, *flag-based* args,
# and auto-skip of IPv6 when the blocklist contains no IPv6.
# Requires: iptables{,-save,-restore}, ipset. ip6tables is optional.

set -euo pipefail

# -------------------------- Defaults (overridable) ----------------------------
BLOCKLIST_DEFAULT="${BLOCKLIST_DEFAULT:-/etc/blocked-out.list}"
BACKUP_DIR_DEFAULT="${BACKUP_DIR_DEFAULT:-/var/lib/ipblocker}"
LOG_LIMIT_DEFAULT="${LOG_LIMIT_DEFAULT:-5/min}"
LOG_LVL_DEFAULT="${LOG_LVL_DEFAULT:-4}"
# -----------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

# ------------------------------- Usage ----------------------------------------
usage() {
  cat <<'EOF'
Usage:
  blacklist.sh apply  --set-name NAME [--blocklist PATH] [--iface IFACE] [--backup-dir DIR]
                                       [--log-limit N/period] [--log-level LVL]
  blacklist.sh clear  --set-name NAME [--delete-sets] [--backup-dir DIR]
  blacklist.sh status --set-name NAME
  blacklist.sh restore [--snapshot PATH|latest] [--backup-dir DIR]

Notes:
  --set-name NAME  (required for apply/clear/status) creates:
     ipsets: NAME_v4, NAME_v6
     chains: OUTBLOCK_NAME_V4, OUTBLOCK_NAME_V6
  IPv6 is automatically skipped if the blocklist contains no IPv6 entries,
  and status output will omit IPv6 if no v6 set/chain exists.

Examples:
  sudo ./blacklist.sh apply  --set-name corpdeny --blocklist /etc/blocked-out.list --iface eth0
  sudo ./blacklist.sh status --set-name corpdeny
  sudo ./blacklist.sh clear  --set-name corpdeny --delete-sets
  sudo ./blacklist.sh restore --snapshot latest
EOF
}

# ------------------------------ Utilities -------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

require_cmd() {
  local cmd="$1" verflag="${2:-}"
  if ! have "$cmd"; then echo "ERROR: '$cmd' not found"; exit 1; fi
  if [[ -n "$verflag" ]]; then { "$cmd" "$verflag" 2>&1 || true; } | head -n1; fi
}

check_deps() {
  echo "== Dependency checks =="
  require_cmd iptables "-V"
  if have ip6tables; then require_cmd ip6tables "-V"; else echo "ip6tables: (not found, IPv6 will be skipped)"; fi
  require_cmd iptables-save
  require_cmd iptables-restore
  if have ip6tables; then require_cmd ip6tables-save; fi
  if have ip6tables; then require_cmd ip6tables-restore; fi
  require_cmd ipset "-v"
  echo
}

nowstamp() { date +"%Y-%m-%dT%H-%M-%S"; }

make_snapshot_dir() {
  local dir="$1/$(nowstamp)"
  mkdir -p "$dir"
  echo "$dir"
}

save_snapshot() {
  local snapdir="$1"
  echo "== Saving snapshot to: $snapdir =="
  $SUDO iptables-save   > "${snapdir}/iptables.v4"
  if have ip6tables; then $SUDO ip6tables-save > "${snapdir}/iptables.v6"; fi
  $SUDO ipset save      > "${snapdir}/ipset.conf"
  echo "Snapshot taken at $(date -Is)" > "${snapdir}/meta.txt"
  echo "$snapdir" | tee "$(dirname "$snapdir")/LATEST" >/dev/null
}

latest_snapshot() {
  local backup_dir="$1"
  if [[ -f "$backup_dir/LATEST" ]]; then
    cat "$backup_dir/LATEST"
  else
    ls -1d "$backup_dir"/* 2>/dev/null | sort | tail -n1
  fi
}

restore_snapshot() {
  local snapdir="$1"
  [[ -d "$snapdir" ]] || { echo "ERROR: snapshot dir not found: $snapdir" >&2; exit 1; }
  echo "== Restoring snapshot from: $snapdir =="
  $SUDO ipset restore      < "${snapdir}/ipset.conf"
  $SUDO iptables-restore   < "${snapdir}/iptables.v4"
  if have ip6tables && [[ -f "${snapdir}/iptables.v6" ]]; then
    $SUDO ip6tables-restore < "${snapdir}/iptables.v6"
  fi
  echo "Restore complete."
}

# -------------- Naming (derived from --set-name, required) --------------------
SET_BASE=""; SET_V4=""; SET_V6=""; CHAIN_V4=""; CHAIN_V6=""
update_names_from_basename() {
  local base="$1"
  [[ -n "$base" ]] || { echo "ERROR: --set-name is required"; exit 1; }
  SET_BASE="$base"
  SET_V4="${SET_BASE}_v4"
  SET_V6="${SET_BASE}_v6"
  CHAIN_V4="OUTBLOCK_${SET_BASE}_V4"
  CHAIN_V6="OUTBLOCK_${SET_BASE}_V6"
}

# -------------------- Existence helpers (avoid noisy output) ------------------
ipset_exists() { $SUDO ipset list "$1" >/dev/null 2>&1; }
chain_exists() { # $1=iptables|ip6tables  $2=CHAIN
  have "$1" && $SUDO "$1" -S "$2" >/dev/null 2>&1
}
any_rules_jump_to_chain() { # $1=iptables|ip6tables  $2=CHAIN
  have "$1" && $SUDO "$1" -S OUTPUT 2>/dev/null | grep -Fq " -j $2"
}

# ---------------------- Blocklist scan (v4/v6 detection) ----------------------
HAS_V4=0
HAS_V6=0
scan_blocklist() {
  local listfile="$1"
  HAS_V4=0; HAS_V6=0
  [[ -f "$listfile" ]] || { echo "ERROR: blocklist not found: $listfile" >&2; exit 1; }
  while read -r a b _; do
    [[ -z "${a:-}" || "${a:0:1}" == "#" ]] && continue
    if [[ "$a" == *:* ]]; then
      HAS_V6=1
    else
      HAS_V4=1
    fi
    # Tiny optimization: stop if both seen
    (( HAS_V4==1 && HAS_V6==1 )) && break || true
  done < "$listfile"
}

# --------------------------- Blocklist loading --------------------------------
prefix_from_mask() {
  local m=$1 sum=0 o n o1 o2 o3 o4
  IFS=. read -r o1 o2 o3 o4 <<< "$m"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    case "$o" in
      255) n=8;; 254) n=7;; 252) n=6;; 248) n=5;;
      240) n=4;; 224) n=3;; 192) n=2;; 128) n=1;;
      0) n=0;;  *) echo "Invalid mask: $m" >&2; return 1;;
    esac
    sum=$((sum+n))
  done
  echo "$sum"
}

load_blocklist_into_ipsets() {
  local listfile="$1"

  # Only create/flush sets that we actually need
  if (( HAS_V4 )); then
    $SUDO ipset create "$SET_V4" hash:net family inet  -exist
    $SUDO ipset flush  "$SET_V4"
  fi
  if (( HAS_V6 )) && have ip6tables; then
    $SUDO ipset create "$SET_V6" hash:net family inet6 -exist
    $SUDO ipset flush  "$SET_V6"
  fi

  while read -r a b _; do
    [[ -z "${a:-}" || "${a:0:1}" == "#" ]] && continue
    if [[ "$a" == *:* ]]; then
      (( HAS_V6 )) && $SUDO ipset add "$SET_V6" "$a" -exist || true
    else
      if (( HAS_V4 )); then
        local entry="$a"
        if [[ -n "${b:-}" ]]; then entry="$a/$(prefix_from_mask "$b")"; fi
        $SUDO ipset add "$SET_V4" "$entry" -exist
      fi
    fi
  done < "$listfile"
}

# --------------------------- Chains & jump rules -------------------------------
ensure_chain_rules_v4() {
  $SUDO iptables -N "$CHAIN_V4" 2>/dev/null || true
  $SUDO iptables -F "$CHAIN_V4"
  $SUDO iptables -A "$CHAIN_V4" -m limit --limit "$LOG_LIMIT" -j LOG --log-prefix "IPBLOCK v4: " --log-level "$LOG_LVL"
  $SUDO iptables -A "$CHAIN_V4" -p tcp -j REJECT --reject-with tcp-reset
  $SUDO iptables -A "$CHAIN_V4" -j REJECT
}

ensure_chain_rules_v6() {
  $SUDO ip6tables -N "$CHAIN_V6" 2>/dev/null || true
  $SUDO ip6tables -F "$CHAIN_V6"
  $SUDO ip6tables -A "$CHAIN_V6" -m limit --limit "$LOG_LIMIT" -j LOG --log-prefix "IPBLOCK v6: " --log-level "$LOG_LVL"
  $SUDO ip6tables -A "$CHAIN_V6" -p tcp -j REJECT --reject-with tcp-reset
  $SUDO ip6tables -A "$CHAIN_V6" -j REJECT
}

ensure_jump_rule() {
  local fam="$1" iface="$2" setname="$3" chainname="$4"
  local ipt IFARG=()
  [[ -n "$iface" ]] && IFARG=(-o "$iface")
  [[ "$fam" == "v4" ]] && ipt="iptables" || ipt="ip6tables"

  if ! $SUDO "$ipt" -C OUTPUT "${IFARG[@]}" -m set --match-set "$setname" dst -j "$chainname" 2>/dev/null; then
    $SUDO "$ipt" -I OUTPUT 1 "${IFARG[@]}" -m set --match-set "$setname" dst -j "$chainname"
  fi
}

remove_jump_rules_and_chains() {
  local ipt="$1" chain="$2"
  if ! have "$ipt"; then return 0; fi
  while read -r line; do
    [[ -z "${line:-}" ]] && continue
    local del="${line/-A /-D }"
    $SUDO "$ipt" $del || true
  done < <($SUDO "$ipt" -S OUTPUT | grep -F " -j $chain" || true)
  $SUDO "$ipt" -F "$chain" 2>/dev/null || true
  $SUDO "$ipt" -X "$chain" 2>/dev/null || true
}

# --------------------------- Status / Printing --------------------------------
print_status() {
  echo
  echo "== Status for set base '$SET_BASE' =="

  if ipset_exists "$SET_V4"; then
    $SUDO ipset list "$SET_V4" | awk '/^Name|Size in memory|Number of entries/ {print}'
  else
    echo "(no IPv4 set present: $SET_V4)"
  fi

  # Only show IPv6 section if a v6 set or chain exists
  if ipset_exists "$SET_V6" || chain_exists ip6tables "$CHAIN_V6" || any_rules_jump_to_chain ip6tables "$CHAIN_V6"; then
    if ipset_exists "$SET_V6"; then
      $SUDO ipset list "$SET_V6" | awk '/^Name|Size in memory|Number of entries/ {print}'
    else
      echo "(no IPv6 set present: $SET_V6)"
    fi
  fi

  echo
  echo "== IPv4 OUTPUT (top 20) =="
  $SUDO iptables -L OUTPUT -n -v --line-numbers | sed -n '1,20p'

  # Only print IPv6 table if v6 chain or jump rules exist
  if chain_exists ip6tables "$CHAIN_V6" || any_rules_jump_to_chain ip6tables "$CHAIN_V6"; then
    echo
    echo "== IPv6 OUTPUT (top 20) =="
    $SUDO ip6tables -L OUTPUT -n -v --line-numbers | sed -n '1,20p'
  fi
}

# ------------------------------- Parsers --------------------------------------
# Accepts "--key value" or "--key=value"
kv() { local k="$1" v="${2:-}"; if [[ "$k" == *=* ]]; then echo "${k#*=}"; else echo "$v"; fi; }

parse_apply() {
  BLOCKLIST="$BLOCKLIST_DEFAULT"; IFACE=""; BACKUP_DIR="$BACKUP_DIR_DEFAULT"
  LOG_LIMIT="$LOG_LIMIT_DEFAULT"; LOG_LVL="$LOG_LVL_DEFAULT"; SETNAME=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --set-name|--set-name=*)  SETNAME="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --blocklist|--blocklist=*) BLOCKLIST="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --iface|--iface=*)        IFACE="$(kv "$1" "${2:-}")";     shift $([[ "$1" == *=* ]] || echo 1);;
      --backup-dir|--backup-dir=*) BACKUP_DIR="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --log-limit|--log-limit=*) LOG_LIMIT="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --log-level|--log-level=*) LOG_LVL="$(kv "$1" "${2:-}")";   shift $([[ "$1" == *=* ]] || echo 1);;
      -h|--help) usage; exit 0;;
      *) echo "Unknown flag for apply: $1"; usage; exit 1;;
    esac; shift || true
  done
  [[ -n "$SETNAME" ]] || { echo "ERROR: --set-name is required for apply"; exit 1; }
}

parse_clear() {
  BACKUP_DIR="$BACKUP_DIR_DEFAULT"; SETNAME=""; DELETE_SETS="no"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --set-name|--set-name=*) SETNAME="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --delete-sets) DELETE_SETS="yes";;
      --backup-dir|--backup-dir=*) BACKUP_DIR="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      -h|--help) usage; exit 0;;
      *) echo "Unknown flag for clear: $1"; usage; exit 1;;
    esac; shift || true
  done
  [[ -n "$SETNAME" ]] || { echo "ERROR: --set-name is required for clear"; exit 1; }
}

parse_status() {
  SETNAME=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --set-name|--set-name=*) SETNAME="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      -h|--help) usage; exit 0;;
      *) echo "Unknown flag for status: $1"; usage; exit 1;;
    esac; shift || true
  done
  [[ -n "$SETNAME" ]] || { echo "ERROR: --set-name is required for status"; exit 1; }
}

parse_restore() {
  BACKUP_DIR="$BACKUP_DIR_DEFAULT"; SNAPSHOT="latest"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --snapshot|--snapshot=*) SNAPSHOT="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      --backup-dir|--backup-dir=*) BACKUP_DIR="$(kv "$1" "${2:-}")"; shift $([[ "$1" == *=* ]] || echo 1);;
      -h|--help) usage; exit 0;;
      *) echo "Unknown flag for restore: $1"; usage; exit 1;;
    esac; shift || true
  done
}

# --------------------------------- Actions ------------------------------------
do_apply() {
  check_deps
  update_names_from_basename "$SETNAME"
  scan_blocklist "$BLOCKLIST"

  if (( HAS_V4==0 && HAS_V6==0 )); then
    echo "NOTE: No IPv4 or IPv6 entries found in '$BLOCKLIST'. Nothing to apply."
    return 0
  fi

  mkdir -p "$BACKUP_DIR"
  local snapdir; snapdir="$(make_snapshot_dir "$BACKUP_DIR")"
  save_snapshot "$snapdir"

  trap 'echo "ERROR occurred. Restoring original rules..."; restore_snapshot "'"$snapdir"'"' ERR INT

  echo "== Loading blocklist '$BLOCKLIST' into ipsets =="; load_blocklist_into_ipsets "$BLOCKLIST"

  if (( HAS_V4 )); then
    echo "== Ensuring chains/rules (IPv4: $CHAIN_V4) =="
    ensure_chain_rules_v4
    ensure_jump_rule "v4" "$IFACE" "$SET_V4" "$CHAIN_V4"
  else
    echo "(Skipping IPv4: no IPv4 entries detected.)"
  fi

  if (( HAS_V6 )) && have ip6tables; then
    echo "== Ensuring chains/rules (IPv6: $CHAIN_V6) =="
    ensure_chain_rules_v6
    ensure_jump_rule "v6" "$IFACE" "$SET_V6" "$CHAIN_V6"
  else
    echo "(Skipping IPv6: no IPv6 entries detected or ip6tables not available.)"
  fi

  trap - ERR INT
  echo "Apply complete."
  print_status
}

do_clear() {
  check_deps
  update_names_from_basename "$SETNAME"

  mkdir -p "$BACKUP_DIR"
  local snapdir; snapdir="$(make_snapshot_dir "$BACKUP_DIR")"
  save_snapshot "$snapdir"

  trap 'echo "ERROR occurred during clear. Restoring original rules..."; restore_snapshot "'"$snapdir"'"' ERR INT

  echo "== Removing OUTPUT jump rules and chains for '$SET_BASE' =="
  remove_jump_rules_and_chains iptables  "$CHAIN_V4"
  # Only touch IPv6 if a v6 chain or set actually exists
  if chain_exists ip6tables "$CHAIN_V6" || ipset_exists "$SET_V6" || any_rules_jump_to_chain ip6tables "$CHAIN_V6"; then
    remove_jump_rules_and_chains ip6tables "$CHAIN_V6"
  fi

  echo "== Clearing ipsets =="
  if ipset_exists "$SET_V4"; then
    if [[ "${DELETE_SETS:-no}" == "yes" ]]; then $SUDO ipset destroy "$SET_V4" 2>/dev/null || true; else $SUDO ipset flush "$SET_V4" 2>/dev/null || true; fi
  fi
  if ipset_exists "$SET_V6"; then
    if [[ "${DELETE_SETS:-no}" == "yes" ]]; then $SUDO ipset destroy "$SET_V6" 2>/dev/null || true; else $SUDO ipset flush "$SET_V6" 2>/dev/null || true; fi
  fi
  [[ "${DELETE_SETS:-no}" == "yes" ]] && echo "Destroyed existing sets." || echo "Flushed existing sets."

  trap - ERR INT
  echo "Clear complete."
  print_status
}

do_status() {
  check_deps
  update_names_from_basename "$SETNAME"
  print_status
}

do_restore() {
  check_deps
  local snapdir="$SNAPSHOT"
  if [[ "$SNAPSHOT" == "latest" ]]; then
    snapdir="$(latest_snapshot "$BACKUP_DIR" || true)"
    [[ -n "$snapdir" ]] || { echo "ERROR: No snapshots found in $BACKUP_DIR"; exit 1; }
  fi
  restore_snapshot "$snapdir"
}

# ----------------------------------- Main -------------------------------------
ACTION="${1:-}"
[[ -z "$ACTION" || "$ACTION" == "-h" || "$ACTION" == "--help" ]] && { usage; exit 0; }
shift

case "$ACTION" in
  apply)   parse_apply   "$@"; do_apply   ;;
  clear)   parse_clear   "$@"; do_clear   ;;
  status)  parse_status  "$@"; do_status  ;;
  restore) parse_restore "$@"; do_restore ;;
  *) echo "Unknown action: $ACTION"; usage; exit 1;;
esac
