#!/usr/bin/env bash
# blacklist.sh — nftables-only outbound blocklist manager
# - Pure bash; no iptables/ipset; no embedded Python.
# - Blocks outbound traffic to listed IPs/ranges using nftables:
#     * table inet blacklist_sh, chain 'out' (hook output): REJECT
#     * table netdev blacklist_sh, chain 'egress_<iface>' (hook egress): DROP (+ VLAN-aware rules)
# - Keeps both layers in-sync on enable/disable/rename.

set -euo pipefail

# ------------------------------- Globals ---------------------------------------
SCRIPT_NAME="$(basename "$0")"
COMMENT_PREFIX="blacklist.sh"
STAMP="$(date +%Y%m%d_%H%M)"

NFT_INET_TABLE="blacklist_sh"
NFT_NETDEV_TABLE="blacklist_sh"
NFT_OUT_CHAIN="out"
NFT_HOOK_PRIO=0

NFT_FAMILY="inet"     # naming retained for compatibility text
HAS_IPV4=0
HAS_IPV6=0
BL_MAX_EXPAND="${BL_MAX_EXPAND:-100000}"

BACKUP_DIR_DEFAULT="/var/backups/blacklist-sh"

# ------------------------------- Utils -----------------------------------------
log() { printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { printf '[%s] ERROR: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*" >&2; exit 1; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then die "This script must be run as root."; fi
}

check_deps() {
  local missing=() dep
  for dep in nft ip awk sed grep tr cut sort uniq tar date; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then die "Missing dependencies: ${missing[*]}"; fi
}

usage() {
cat <<'USAGE'
Usage:
  blacklist.sh create          -bl <file|csv-nmap> [-sn NAME]
  blacklist.sh enable          -sn NAME [-i IFACE]
  blacklist.sh disable         -sn NAME
  blacklist.sh rename          -sn OLD -nn NEW
  blacklist.sh list-sets       [-sn NAME|all]
  blacklist.sh list-tables   [-sn NAME|all]
  blacklist.sh status          [-sn NAME]
  blacklist.sh flush-table  -sn NAME|all
  blacklist.sh flush-set     -sn NAME|all
  blacklist.sh destroy-set   -sn NAME|all
  blacklist.sh backup          [-d DIR]
  blacklist.sh restore         -f /path/to/backup.tar.gz

Options:
  -bl, --blocklist   File path OR comma-separated list. Supports:
                     IPv4/IPv6, CIDR, "IPv4 NETMASK", and nmap-style IPv4 (e.g., 10.0.0-3.1-254).
  -sn, --set-name    Name of the block set (default: YYYYMMDD_HHMM for 'create').
  -nn, --new-name    New set name for 'rename'.
  -i,  --iface       Interface to apply rules on (default: system default route).
                     Use "-i all" for ALL non-loopback interfaces.
  -d,  --dir         Backup directory (default: /var/backups/blacklist-sh).
  -f,  --file        Backup archive to restore.

Notes:
  • Outbound-only enforcement: inet/output (reject) + netdev/egress (drop w/ VLAN support).
  • 'create' only creates/loads the nft sets. Use 'enable' to enforce, 'disable' to remove.
USAGE
}

# ------------------------------- Interfaces ------------------------------------
default_iface() {
  local dev
  dev="$(ip -4 route show default 2>/dev/null | awk '/^default/ {for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')"
  if [[ -z "$dev" ]]; then
    dev="$(ip -6 route show default 2>/dev/null | awk '/^default/ {for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')"
  fi
  [[ -n "$dev" ]] || die "Unable to determine default interface; specify -i/--iface."
  printf '%s\n' "$dev"
}

all_ifaces() {
  ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*$//' | grep -v '^lo$' | sort -u
}

resolve_iface_hint() {
  local in="${1:-}"
  if [[ -z "$in" ]]; then default_iface
  else
    local lc; lc="$(printf '%s' "$in" | tr '[:upper:]' '[:lower:]')"
    case "$lc" in all|any|'*') echo "all";; *) echo "$in" | sed 's/@.*$//';; esac
  fi
}

# ------------------------------- Parsers ---------------------------------------
is_ipv4_cidr_or_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; }
is_ipv6_any() { [[ "$1" == *:* ]] && return 0 || return 1; }
is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

mask_to_prefix() {
  local m="$1" o1 o2 o3 o4
  IFS=. read -r o1 o2 o3 o4 <<<"$m"
  for n in "$o1" "$o2" "$o3" "$o4"; do
    case "$n" in 0|128|192|224|240|248|252|254|255) ;; *) die "Invalid netmask octet: $n";; esac
  done
  local -a bits=(0 1 1 2 1 2 2 3 1 2 2 3 2 3 3 4)
  local add=0 oct; for oct in $o1 $o2 $o3 $o4; do add=$((add + bits[oct/16] + bits[oct%16])); done
  printf '%s\n' "$add"
}

normalize_entry_basic() {
  local raw="$1" ip nm
  raw="$(echo "$raw" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ -n "$raw" ]] || return 1
  if [[ "$raw" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})[[:space:]]+([0-9]{1,3}(\.[0-9]{1,3}){3})$ ]]; then
    ip="${BASH_REMATCH[1]}"; nm="${BASH_REMATCH[3]}"; HAS_IPV4=1
    printf '%s/%s\n' "$ip" "$(mask_to_prefix "$nm")"; return 0
  fi
  if is_ipv4_cidr_or_ip "$raw"; then HAS_IPV4=1; printf '%s\n' "$raw"; return 0; fi
  if is_ipv6_any "$raw"; then HAS_IPV6=1; printf '%s\n' "$raw"; return 0; fi
  return 1
}

parse_oct_range() {
  local spec="$1" a b
  if [[ "$spec" =~ ^[0-9]+-[0-9]+$ ]]; then
    IFS=- read -r a b <<<"$spec"; is_uint "$a" && is_uint "$b" || return 1
    ((a>=0 && a<=255 && b>=0 && b<=255 && a<=b)) || return 1
    echo "$a $b"
  elif is_uint "$spec"; then
    ((spec>=0 && spec<=255)) || return 1; echo "$spec $spec"
  else
    return 1
  fi
}

expand_csv_nmapstyle() {
  local csv="$1" tok
  IFS=, read -ra TOKS <<<"$csv"
  for tok in "${TOKS[@]}"; do
    tok="$(echo "$tok" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -z "$tok" ]] && continue
    if normalize_entry_basic "$tok"; then continue; fi
    local p0 p1 p2 p3
    IFS='.' read -r p0 p1 p2 p3 <<<"$tok"
    [[ -n "$p0" && -n "$p1" && -n "$p2" && -n "$p3" ]] || die "Unrecognized token '$tok'"
    local r0 r1 r2 r3 a0 b0 a1 b1 a2 b2 a3 b3
    r0="$(parse_oct_range "$p0")" || die "Bad nmap-style range '$tok'"
    r1="$(parse_oct_range "$p1")" || die "Bad nmap-style range '$tok'"
    r2="$(parse_oct_range "$p2")" || die "Bad nmap-style range '$tok'"
    r3="$(parse_oct_range "$p3")" || die "Bad nmap-style range '$tok'"
    read -r a0 b0 <<<"$r0"; read -r a1 b1 <<<"$r1"; read -r a2 b2 <<<"$r2"; read -r a3 b3 <<<"$r3"
    if [[ "$p0" != *-* && "$p1" != *-* && "$p2" != *-* && "$p3" != *-* ]]; then die "Unrecognized token '$tok'"; fi
    local c0=$((b0-a0+1)) c1=$((b1-a1+1)) c2=$((b2-a2+1)) c3=$((b3-a3+1)) total=$((c0*c1*c2*c3))
    (( total <= BL_MAX_EXPAND )) || die "Expansion of '$tok' would produce ${total} IPs (> ${BL_MAX_EXPAND}). Use CIDR."
    HAS_IPV4=1
    local A B C D
    for ((A=a0; A<=b0; A++)); do
      for ((B=a1; B<=b1; B++)); do
        for ((C=a2; C<=b2; C++)); do
          for ((D=a3; D<=b3; D++)); do
            printf '%d.%d.%d.%d\n' "$A" "$B" "$C" "$D"
          done
        done
      done
    done
  done
}

parse_blocklist_arg() {
  local src="$1"
  if [[ -e "$src" && ! -d "$src" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(echo "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      [[ -z "$line" ]] && continue
      expand_csv_nmapstyle "$line"
    done < "$src"
  else
    [[ -d "$src" ]] && die "-bl points to a directory: $src"
    expand_csv_nmapstyle "$src"
  fi
}

# ------------------------------- nft helpers -----------------------------------
nft_ensure_inet() {
  nft list table inet "$NFT_INET_TABLE" >/dev/null 2>&1 || nft add table inet "$NFT_INET_TABLE"
  nft list chain inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" >/dev/null 2>&1 || \
    nft add chain inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" "{ type filter hook output priority $NFT_HOOK_PRIO; }"
}

nft_ensure_netdev() {
  nft list table netdev "$NFT_NETDEV_TABLE" >/dev/null 2>&1 || nft add table netdev "$NFT_NETDEV_TABLE"
}

nft_chain_netdev_for_iface() {
  local iface="$1"
  printf 'egress_%s' "$iface"
}

nft_ensure_netdev_chain_iface() {
  local iface="$1" chain
  chain="$(nft_chain_netdev_for_iface "$iface")"
  nft list chain netdev "$NFT_NETDEV_TABLE" "$chain" >/dev/null 2>&1 || \
    nft add chain netdev "$NFT_NETDEV_TABLE" "$chain" "{ type filter hook egress device \"$iface\" priority $NFT_HOOK_PRIO; }"
}

nft_set_v4() { printf 'v4_%s' "$1"; }
nft_set_v6() { printf 'v6_%s' "$1"; }

nft_ensure_sets_for_set() {
  local set="$1" v4 v6
  v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"
  nft_ensure_inet
  nft list set inet "$NFT_INET_TABLE" "$v4" >/dev/null 2>&1 || nft add set inet "$NFT_INET_TABLE" "$v4" '{ type ipv4_addr; flags interval; }'
  nft list set inet "$NFT_INET_TABLE" "$v6" >/dev/null 2>&1 || nft add set inet "$NFT_INET_TABLE" "$v6" '{ type ipv6_addr; flags interval; }'
  nft_ensure_netdev
  nft list set netdev "$NFT_NETDEV_TABLE" "$v4" >/dev/null 2>&1 || nft add set netdev "$NFT_NETDEV_TABLE" "$v4" '{ type ipv4_addr; flags interval; }'
  nft list set netdev "$NFT_NETDEV_TABLE" "$v6" >/dev/null 2>&1 || nft add set netdev "$NFT_NETDEV_TABLE" "$v6" '{ type ipv6_addr; flags interval; }'
}

nft_add_elements_dual() {
  local set="$1"; shift
  local v4 v6 elem
  v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"
  for elem in "$@"; do
    if [[ "$elem" == *:* ]]; then
      nft add element inet  "$NFT_INET_TABLE"   "$v6" "{ $elem }"
      nft add element netdev "$NFT_NETDEV_TABLE" "$v6" "{ $elem }"
      HAS_IPV6=1
    else
      nft add element inet  "$NFT_INET_TABLE"   "$v4" "{ $elem }"
      nft add element netdev "$NFT_NETDEV_TABLE" "$v4" "{ $elem }"
      HAS_IPV4=1
    fi
  done
}

nft_flush_set_dual() {
  local set="$1" v4 v6
  v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"
  nft flush set inet  "$NFT_INET_TABLE" "$v4" 2>/dev/null || true
  nft flush set inet  "$NFT_INET_TABLE" "$v6" 2>/dev/null || true
  nft flush set netdev "$NFT_NETDEV_TABLE" "$v4" 2>/dev/null || true
  nft flush set netdev "$NFT_NETDEV_TABLE" "$v6" 2>/dev/null || true
}

nft_destroy_set_dual() {
  local set="$1" v4 v6
  v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"
  nft delete set inet  "$NFT_INET_TABLE" "$v4" 2>/dev/null || true
  nft delete set inet  "$NFT_INET_TABLE" "$v6" 2>/dev/null || true
  nft delete set netdev "$NFT_NETDEV_TABLE" "$v4" 2>/dev/null || true
  nft delete set netdev "$NFT_NETDEV_TABLE" "$v6" 2>/dev/null || true
}

out_rule_comment() { printf '%s:%s:%s' "$COMMENT_PREFIX" "$1" "out"; }
egress_rule_comment() { printf '%s:%s:%s' "$COMMENT_PREFIX" "$1" "egress"; }

nft_rule_exists_out() {
  local set="$1"
  nft list chain inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" 2>/dev/null | grep -q "comment \"$(out_rule_comment "$set")\"" && return 0 || return 1
}

# -------------------------- ADD RULES (with quoted comments) -------------------
nft_add_out_rules() {
  local set="$1" iface="${2:-}"
  nft_ensure_inet
  local v4 v6 comment; v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"; comment="$(out_rule_comment "$set")"
  if [[ -z "${iface:-}" || "${iface}" == "all" || "${iface}" == "any" || "${iface}" == "*" ]]; then
    nft add rule inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" ip  daddr @"$v4" reject with icmpx type admin-prohibited comment \""$comment"\"
    nft add rule inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" ip6 daddr @"$v6" reject with icmpx type admin-prohibited comment \""$comment"\"
  else
    nft add rule inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" oifname "$iface" ip  daddr @"$v4" reject with icmpx type admin-prohibited comment \""$comment"\"
    nft add rule inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" oifname "$iface" ip6 daddr @"$v6" reject with icmpx type admin-prohibited comment \""$comment"\"
  fi
}

nft_add_netdev_rules_for_iface() {
  local set="$1" iface="$2" v4 v6 comment chain
  nft_ensure_netdev
  nft_ensure_netdev_chain_iface "$iface"
  v4="$(nft_set_v4 "$set")"; v6="$(nft_set_v6 "$set")"; chain="$(nft_chain_netdev_for_iface "$iface")"
  comment="$(egress_rule_comment "$set")"
  nft add rule netdev "$NFT_NETDEV_TABLE" "$chain" ip  daddr @"$v4" drop comment \""$comment"\"
  nft add rule netdev "$NFT_NETDEV_TABLE" "$chain" ip6 daddr @"$v6" drop comment \""$comment"\"
  nft add rule netdev "$NFT_NETDEV_TABLE" "$chain" vlan type ip  ip  daddr @"$v4" drop comment \""$comment"\"
  nft add rule netdev "$NFT_NETDEV_TABLE" "$chain" vlan type ip6 ip6 daddr @"$v6" drop comment \""$comment"\"
}

# Delete rules by comment (handles across tables/chains)
nft_delete_rules_by_comment() {
  local family="$1" table="$2" comment="$3"
  nft -a list table "$family" "$table" 2>/dev/null | \
    awk -v c="$comment" '
      $1=="chain" {ch=$2}
      / handle [0-9]+/ && index($0,c)>0 {for(i=1;i<=NF;i++) if($i=="handle") print ch" " $(i+1)}
    ' | while read -r ch h; do
      nft delete rule "$family" "$table" "$ch" handle "$h" 2>/dev/null || true
    done
}

# Discover which netdev egress chains currently carry this set's rules
nft_existing_ifaces_for_set() {
  local set="$1" comment
  comment="$(egress_rule_comment "$set")"
  nft list table netdev "$NFT_NETDEV_TABLE" 2>/dev/null | \
    awk -v c="$comment" '
      $1=="chain" && $2 ~ /^egress_/ {ch=$2}
      index($0,c)>0 {print ch}
    ' | sed 's/^egress_//'
}

# ------------------------------ High-level ops ---------------------------------
ensure_sets_and_load() {
  local setname="$1"; shift
  nft_ensure_sets_for_set "$setname"
  [[ $# -gt 0 ]] || die "No valid blocklist entries were parsed."
  nft_add_elements_dual "$setname" "$@"
  local v4 v6 c4 c6
  v4="$(nft_set_v4 "$setname")"; v6="$(nft_set_v6 "$setname")"
  c4="$(nft list set inet "$NFT_INET_TABLE" "$v4" 2>/dev/null | awk '/elements/ {print}' | wc -c | tr -d ' ')"
  c6="$(nft list set inet "$NFT_INET_TABLE" "$v6" 2>/dev/null | awk '/elements/ {print}' | wc -c | tr -d ' ')"
  log "nft sets ready for '$setname' (v4:${c4:-0}b, v6:${c6:-0}b)."
}

enable_rules() {
  local set="$1" iface_in="${2:-}"
  local iface; iface="$(resolve_iface_hint "$iface_in")"
  nft_add_out_rules "$set" "$iface"
  if [[ "$iface" == "all" ]]; then
    all_ifaces | while read -r ifc; do [[ -n "$ifc" ]] && nft_add_netdev_rules_for_iface "$set" "$ifc"; done
  else
    nft_add_netdev_rules_for_iface "$set" "$iface"
  fi
  log "Enabled nft rules for set '$set' on iface '${iface}'."
}

disable_rules() {
  local set="$1"
  nft_delete_rules_by_comment inet  "$NFT_INET_TABLE"   "$(out_rule_comment "$set")"
  nft_delete_rules_by_comment netdev "$NFT_NETDEV_TABLE" "$(egress_rule_comment "$set")"
  log "Disabled nft rules for set '$set'."
}

rename_set() {
  local old="$1" new="$2"
  [[ -n "$old" && -n "$new" ]] || die "'rename' requires -sn OLD and -nn NEW."

  local existing_ifaces; existing_ifaces="$(nft_existing_ifaces_for_set "$old" || true)"

  local v4o v6o v4n v6n
  v4o="$(nft_set_v4 "$old")"; v6o="$(nft_set_v6 "$old")"
  v4n="$(nft_set_v4 "$new")"; v6n="$(nft_set_v6 "$new")"

  nft_ensure_inet; nft_ensure_netdev
  if nft list set inet "$NFT_INET_TABLE" "$v4n" >/dev/null 2>&1; then
    nft add element inet "$NFT_INET_TABLE" "$v4n" "{ $(nft list set inet "$NFT_INET_TABLE" "$v4o" | awk -F'=' '/elements/{print $2}' | sed 's/[{};]//g') }" 2>/dev/null || true
    nft delete set inet "$NFT_INET_TABLE" "$v4o" 2>/dev/null || true
  else
    nft rename set inet "$NFT_INET_TABLE" "$v4o" "$v4n"
  fi
  if nft list set inet "$NFT_INET_TABLE" "$v6n" >/dev/null 2>&1; then
    nft add element inet "$NFT_INET_TABLE" "$v6n" "{ $(nft list set inet "$NFT_INET_TABLE" "$v6o" | awk -F'=' '/elements/{print $2}' | sed 's/[{};]//g') }" 2>/dev/null || true
    nft delete set inet "$NFT_INET_TABLE" "$v6o" 2>/dev/null || true
  else
    nft rename set inet "$NFT_INET_TABLE" "$v6o" "$v6n"
  fi
  if nft list set netdev "$NFT_NETDEV_TABLE" "$v4n" >/dev/null 2>&1; then
    nft add element netdev "$NFT_NETDEV_TABLE" "$v4n" "{ $(nft list set netdev "$NFT_NETDEV_TABLE" "$v4o" | awk -F'=' '/elements/{print $2}' | sed 's/[{};]//g') }" 2>/dev/null || true
    nft delete set netdev "$NFT_NETDEV_TABLE" "$v4o" 2>/dev/null || true
  else
    nft rename set netdev "$NFT_NETDEV_TABLE" "$v4o" "$v4n"
  fi
  if nft list set netdev "$NFT_NETDEV_TABLE" "$v6n" >/dev/null 2>&1; then
    nft add element netdev "$NFT_NETDEV_TABLE" "$v6n" "{ $(nft list set netdev "$NFT_NETDEV_TABLE" "$v6o" | awk -F'=' '/elements/{print $2}' | sed 's/[{};]//g') }" 2>/dev/null || true
    nft delete set netdev "$NFT_NETDEV_TABLE" "$v6o" 2>/dev/null || true
  else
    nft rename set netdev "$NFT_NETDEV_TABLE" "$v6o" "$v6n"
  fi

  disable_rules "$old"
  if [[ -n "$existing_ifaces" ]]; then
    while read -r ifc; do [[ -n "$ifc" ]] && enable_rules "$new" "$ifc"; done <<< "$existing_ifaces"
  fi
  log "Renamed set '$old' -> '$new' and updated nft rules."
}

list_sets() {
  local which="${1:-all}"
  if [[ "$which" == "all" || -z "$which" ]]; then
    echo "### inet:$NFT_INET_TABLE sets:"
    nft list table inet "$NFT_INET_TABLE" 2>/dev/null || echo "  (none)"
    echo; echo "### netdev:$NFT_NETDEV_TABLE sets:"
    nft list table netdev "$NFT_NETDEV_TABLE" 2>/dev/null || echo "  (none)"
  else
    local v4 v6; v4="$(nft_set_v4 "$which")"; v6="$(nft_set_v6 "$which")"
    echo "### inet sets for '$which':"
    nft list set inet "$NFT_INET_TABLE" "$v4" 2>/dev/null || echo "  (no v4 set)"; echo
    nft list set inet "$NFT_INET_TABLE" "$v6" 2>/dev/null || echo "  (no v6 set)"; echo
    echo "### netdev sets for '$which':"
    nft list set netdev "$NFT_NETDEV_TABLE" "$v4" 2>/dev/null || echo "  (no v4 set)"; echo
    nft list set netdev "$NFT_NETDEV_TABLE" "$v6" 2>/dev/null || echo "  (no v6 set)"
  fi
}

list_rules() {
  local which="${1:-all}"
  if [[ "$which" == "all" ]]; then
    echo "### inet rules (chain: $NFT_OUT_CHAIN):"
    nft list chain inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" 2>/dev/null || echo "  (none)"
    echo; echo "### netdev rules:"
    nft list table netdev "$NFT_NETDEV_TABLE" 2>/dev/null || echo "  (none)"
  else
    local c_out c_eg
    c_out="$(out_rule_comment "$which")"; c_eg="$(egress_rule_comment "$which")"
    echo "### inet rules for '$which':"
    nft list chain inet "$NFT_INET_TABLE" "$NFT_OUT_CHAIN" 2>/dev/null | grep -F "$c_out" || echo "  (none)"
    echo; echo "### netdev rules for '$which':"
    nft list table netdev "$NFT_NETDEV_TABLE" 2>/dev/null | grep -F "$c_eg" || echo "  (none)"
  fi
}

status_set() {
  local set="${1:-all}"
  if [[ "$set" == "all" ]]; then
    echo "### Sets overview:"
    list_sets "all"
    echo; echo "### Rules overview:"
    list_rules "all"
    return 0
  fi
  echo "### Sets for '$set':"; list_sets "$set"
  echo; echo "### Rules for '$set':"; list_rules "$set"
}

flush_rules() {
  local target="$1"
  if [[ "$target" == "all" ]]; then
    nft_delete_rules_by_comment inet  "$NFT_INET_TABLE"   "${COMMENT_PREFIX}:"
    nft_delete_rules_by_comment netdev "$NFT_NETDEV_TABLE" "${COMMENT_PREFIX}:"
    log "Flushed all nft rules managed by ${COMMENT_PREFIX}."
  else
    disable_rules "$target"
  fi
}

flush_sets() {
  local target="$1"
  if [[ "$target" == "all" ]]; then
    for fam in inet netdev; do
      nft list table "$fam" "$([[ $fam == inet ]] && echo $NFT_INET_TABLE || echo $NFT_NETDEV_TABLE)" 2>/dev/null | \
        awk '/^ *set (v[46]_[^ ]+)/ {print $2}' | while read -r s; do
          nft flush set "$fam" "$([[ $fam == inet ]] && echo $NFT_INET_TABLE || echo $NFT_NETDEV_TABLE)" "$s" 2>/dev/null || true
        done
    done
    log "Flushed all v4_/v6_ sets."
  else
    nft_flush_set_dual "$target"
    log "Flushed sets for '$target'."
  fi
}

destroy_sets() {
  local target="$1"
  if [[ "$target" == "all" ]]; then
    flush_rules "all"
    for fam in inet netdev; do
      nft list table "$fam" "$([[ $fam == inet ]] && echo $NFT_INET_TABLE || echo $NFT_NETDEV_TABLE)" 2>/dev/null | \
        awk '/^ *set (v[46]_[^ ]+)/ {print $2}' | while read -r s; do
          nft delete set "$fam" "$([[ $fam == inet ]] && echo $NFT_INET_TABLE || echo $NFT_NETDEV_TABLE)" "$s" 2>/dev/null || true
        done
    done
    log "Destroyed all v4_/v6_ sets."
  else
    disable_rules "$target"
    nft_destroy_set_dual "$target"
    log "Destroyed sets for '$target'."
  fi
}

backup_configs() {
  local outdir="${1:-$BACKUP_DIR_DEFAULT}"
  mkdir -p "$outdir"
  local tmpdir; tmpdir="$(mktemp -d)"
  nft list ruleset > "$tmpdir/nft.ruleset"
  local tarpath="$outdir/blacklist-backup-${STAMP}.tar.gz"
  tar -C "$tmpdir" -czf "$tarpath" .
  rm -rf "$tmpdir"
  echo "Backup created: $tarpath"
}

restore_configs() {
  local archive="$1"
  [[ -f "$archive" ]] || die "Backup archive not found: $archive"
  local tmpdir; tmpdir="$(mktemp -d)"
  tar -C "$tmpdir" -xzf "$archive"
  [[ -f "$tmpdir/nft.ruleset" ]] || die "nft.ruleset not found in archive."
  nft -f "$tmpdir/nft.ruleset"
  rm -rf "$tmpdir"
  echo "Restore completed from: $archive"
}

# ------------------------------- CLI Parsing -----------------------------------
cmd="${1:-}"; [[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]] && { usage; exit 0; }
shift || true

require_root
check_deps

SET_NAME=""
NEW_NAME=""
BLOCKLIST_ARG=""
IFACE=""
BACKUP_DIR="$BACKUP_DIR_DEFAULT"
BACKUP_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -sn|--set-name)    SET_NAME="${2:-}"; shift 2;;
    -nn|--new-name)    NEW_NAME="${2:-}"; shift 2;;
    -bl|--blocklist)   BLOCKLIST_ARG="${2:-}"; shift 2;;
    -i|--iface)        IFACE="${2:-}"; shift 2;;
    -d|--dir)          BACKUP_DIR="${2:-}"; shift 2;;
    -f|--file)         BACKUP_FILE="${2:-}"; shift 2;;
    -h|--help)         usage; exit 0;;
    --) shift; break;;
    *) die "Unknown option: $1";;
  esac
done

# ------------------------------- Commands --------------------------------------
case "$cmd" in
  create)
    [[ -n "$SET_NAME" ]] || SET_NAME="$STAMP"
    [[ -n "$BLOCKLIST_ARG" ]] || die "'create' requires -bl/--blocklist."
    mapfile -t ENTRIES < <(parse_blocklist_arg "$BLOCKLIST_ARG")
    HAS_IPV4=0; HAS_IPV6=0
    nft_ensure_sets_for_set "$SET_NAME"
    ensure_sets_and_load "$SET_NAME" "${ENTRIES[@]}"
    log "Set '$SET_NAME' created/loaded. Use 'enable -sn $SET_NAME [-i IFACE]' to enforce."
    ;;

  enable)
    [[ -n "$SET_NAME" ]] || die "'enable' requires -sn/--set-name."
    nft_ensure_sets_for_set "$SET_NAME"
    enable_rules "$SET_NAME" "${IFACE:-}"
    ;;

  disable)
    [[ -n "$SET_NAME" ]] || die "'disable' requires -sn/--set-name."
    disable_rules "$SET_NAME"
    ;;

  rename)
    [[ -n "$SET_NAME" && -n "$NEW_NAME" ]] || die "'rename' requires -sn OLD and -nn NEW."
    rename_set "$SET_NAME" "$NEW_NAME"
    ;;

  list-sets)
    if [[ -z "${SET_NAME:-}" || "${SET_NAME}" == "all" ]]; then list_sets "all"; else list_sets "$SET_NAME"; fi
    ;;

  list-tables)
    if [[ -z "${SET_NAME:-}" || "${SET_NAME}" == "all" ]]; then list_rules "all"; else list_rules "$SET_NAME"; fi
    ;;

  status)
    status_set "${SET_NAME:-all}"
    ;;

  flush-table)
    [[ -n "$SET_NAME" ]] || die "'flush-table' requires -sn NAME|all."
    flush_rules "$SET_NAME"
    ;;

  flush-set)
    [[ -n "$SET_NAME" ]] || die "'flush-set' requires -sn NAME|all."
    flush_sets "$SET_NAME"
    ;;

  destroy-set)
    [[ -n "$SET_NAME" ]] || die "'destroy-set' requires -sn NAME|all."
    destroy_sets "$SET_NAME"
    ;;

  backup)
    backup_configs "$BACKUP_DIR"
    ;;

  restore)
    [[ -n "$BACKUP_FILE" ]] || die "'restore' requires -f /path/to/backup.tar.gz."
    restore_configs "$BACKUP_FILE"
    ;;

  *)
    die "Unknown command: $cmd (run with --help for usage)."
    ;;
esac
