#!/usr/bin/env bash
# subnet_chunker.sh
# Requirements: bash 4+, GNU coreutils (sort -V preferred; fallbacks included)

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: subnet_chunker.sh [-m NETMASK|PREFIX | -H HOSTS] [-o DIR] INPUT_FILE

  INPUT_FILE: Text file with one subnet per line, either:
              - CIDR notation:             10.0.0.0/24
              - "network mask" notation:   10.0.0.0 255.255.255.0
              Blank lines and lines starting with '#' are ignored.

Options:
  -m NETMASK  Target subnet size by netmask (e.g., 255.255.255.128) or CIDR prefix (e.g., 25).
  -H HOSTS    Target usable hosts per subnet (e.g., 50). The script chooses the
              smallest subnet that can fit at least this many hosts (classic IPv4).
  -o DIR      Output directory for generated files. Defaults to current working directory.
  -h          Show this help.

Outputs:
  DIR/broadcast_addresses  - broadcast IPs only; deduplicated and version-sorted
  DIR/chunked_subnets      - CIDR subnets after chunking (or normalized originals if no -m/-H);
                             deduplicated and sorted by IP then prefix
USAGE
}

# ---------- IPv4 helpers ----------

ip2int() {
  local ip=$1 o1 o2 o3 o4
  IFS=. read -r o1 o2 o3 o4 <<<"$ip" || return 1
  [[ $o1 =~ ^[0-9]+$ && $o2 =~ ^[0-9]+$ && $o3 =~ ^[0-9]+$ && $o4 =~ ^[0-9]+$ ]] || return 1
  (( o1<=255 && o2<=255 && o3<=255 && o4<=255 )) || return 1
  echo $(( (o1<<24) | (o2<<16) | (o3<<8) | o4 ))
}

int2ip() {
  local n=$1
  echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"
}

prefix2mask_int() {
  local p=$1
  (( p>=0 && p<=32 )) || return 1
  if (( p==0 )); then
    echo 0
  else
    echo $(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
  fi
}

mask2prefix() {
  local mask=$1 m int p
  int=$(ip2int "$mask") || return 1
  for (( p=0; p<=32; p++ )); do
    m=$(prefix2mask_int "$p")
    if (( m == int )); then
      echo "$p"
      return 0
    fi
  done
  return 1
}

normalize_cidr() {
  local ip=$1 prefix=$2 ipi mask net
  ipi=$(ip2int "$ip") || return 1
  mask=$(prefix2mask_int "$prefix") || return 1
  net=$(( ipi & mask ))
  echo "$(int2ip "$net")/$prefix"
}

cidr_broadcast() {
  local ip=$1 prefix=$2 ipi mask net bcast
  ipi=$(ip2int "$ip") || return 1
  mask=$(prefix2mask_int "$prefix") || return 1
  net=$(( ipi & mask ))
  bcast=$(( net | (~mask & 0xFFFFFFFF) ))
  int2ip "$bcast"
}

parse_line_to_netprefix() {
  local line=$1 ip prefix mask token1 token2
  if [[ $line =~ ^[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]{1,2})[[:space:]]*$ ]]; then
    ip="${BASH_REMATCH[1]}"
    prefix="${BASH_REMATCH[2]}"
    (( prefix>=0 && prefix<=32 )) || return 1
    token1=$(normalize_cidr "$ip" "$prefix") || return 1
    echo "${token1%/*} ${token1#*/}"
    return 0
  fi
  read -r token1 token2 <<<"$line" || true
  if [[ -n ${token1:-} && -n ${token2:-} ]]; then
    ip="$token1"
    mask="$token2"
    prefix=$(mask2prefix "$mask") || return 1
    token1=$(normalize_cidr "$ip" "$prefix") || return 1
    echo "${token1%/*} ${token1#*/}"
    return 0
  fi
  return 1
}

usable_hosts_for_prefix() {
  local p=$1 total usable
  (( p>=0 && p<=32 )) || { echo 0; return; }
  total=$(( 1 << (32 - p) ))
  if (( p==31 || p==32 )); then
    usable=0
  else
    usable=$(( total - 2 ))
  fi
  echo "$usable"
}

prefix_for_hosts() {
  local need=$1 p usable
  if (( need <= 0 )); then echo 32; return; fi
  for (( p=32; p>=0; p-- )); do
    usable=$(usable_hosts_for_prefix "$p")
    if (( usable >= need )); then echo "$p"; return 0; fi
  done
  echo 0
}

split_to_prefix() {
  local netip=$1 pc=$2 pt=$3
  if (( pt < pc )) || (( pt == pc )); then
    echo "$(int2ip "$netip")/$pc"
    return 0
  fi
  local blocks=$(( 1 << (pt - pc) ))
  local step=$(( 1 << (32 - pt) ))
  local i sub
  for (( i=0; i<blocks; i++ )); do
    sub=$(( netip + i*step ))
    echo "$(int2ip "$sub")/$pt"
  done
}

# ----- Sorting helpers -----

# Deduplicate + version-sort a file of IPv4s (one per line).
dedupe_and_versionsort_ips() {
  local f=$1
  if sort -V -u "$f" > "$f.tmp" 2>/dev/null; then
    mv "$f.tmp" "$f"
    return 0
  fi
  # Fallback: zero-pad octets, sort unique, then strip padding
  awk -F. 'NF==4 { printf "%03d.%03d.%03d.%03d|%s\n", $1,$2,$3,$4,$0 }' "$f" \
    | sort -u \
    | cut -d'|' -f2- > "$f.tmp"
  mv "$f.tmp" "$f"
}

# Deduplicate + sort CIDRs (IPv4/prefix). Prefers sort -V; fallback is numeric on ip then prefix.
dedupe_and_sort_cidrs() {
  local f=$1
  if sort -V -u "$f" > "$f.tmp" 2>/dev/null; then
    mv "$f.tmp" "$f"
    return 0
  fi
  # Fallback: pad IP octets and prefix to 3 digits
  awk -F'[./]' 'NF==5 {
      printf "%03d.%03d.%03d.%03d/%03d|%s\n", $1,$2,$3,$4,$5,$0
    }' "$f" \
    | sort -u \
    | cut -d'|' -f2- > "$f.tmp"
  mv "$f.tmp" "$f"
}

# ---------- CLI parsing ----------

target_prefix=""
hosts_param=""
mask_param=""
out_dir="$PWD"

while getopts ":m:H:o:h" opt; do
  case "$opt" in
    m) mask_param="$OPTARG" ;;
    H) hosts_param="$OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Error: Invalid option -$OPTARG" >&2; usage; exit 2 ;;
    :)  echo "Error: Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))

if (( $# != 1 )); then
  echo "Error: Exactly one INPUT_FILE is required." >&2
  usage
  exit 2
fi

input_file="$1"
[[ -r "$input_file" ]] || { echo "Error: Cannot read input file: $input_file" >&2; exit 2; }

# Ensure output directory exists and is writable
mkdir -p "$out_dir" 2>/dev/null || { echo "Error: Cannot create output directory: $out_dir" >&2; exit 2; }
[[ -w "$out_dir" ]] || { echo "Error: Output directory not writable: $out_dir" >&2; exit 2; }

if [[ -n "$mask_param" && -n "$hosts_param" ]]; then
  echo "Error: Use only one of -m or -H, not both." >&2
  exit 2
fi

if [[ -n "$mask_param" ]]; then
  if [[ $mask_param =~ ^[0-9]{1,2}$ ]]; then
    (( mask_param>=0 && mask_param<=32 )) || { echo "Error: invalid prefix $mask_param" >&2; exit 2; }
    target_prefix="$mask_param"
  else
    target_prefix="$(mask2prefix "$mask_param")" || { echo "Error: invalid netmask $mask_param" >&2; exit 2; }
  fi
elif [[ -n "$hosts_param" ]]; then
  [[ $hosts_param =~ ^[0-9]+$ ]] || { echo "Error: -H requires a positive integer." >&2; exit 2; }
  target_prefix="$(prefix_for_hosts "$hosts_param")"
fi

# ---------- Processing ----------

bcast_file="$out_dir/broadcast_addresses"
chunk_file="$out_dir/chunked_subnets"
: > "$bcast_file"
: > "$chunk_file"

while IFS= read -r rawline || [[ -n "$rawline" ]]; do
  line="${rawline%$'\r'}"
  [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue

  if ! parsed=$(parse_line_to_netprefix "$line"); then
    echo "Warning: Skipping invalid line: $line" >&2
    continue
  fi

  read -r netip prefix <<<"$parsed"

  # Broadcast (write only the address)
  bcast=$(cidr_broadcast "$netip" "$prefix")
  echo "$bcast" >> "$bcast_file"

  # Chunking output
  net_int=$(ip2int "$netip")
  if [[ -n "$target_prefix" ]]; then
    while IFS= read -r sub; do
      echo "$sub" >> "$chunk_file"
    done < <(split_to_prefix "$net_int" "$prefix" "$target_prefix")
  else
    echo "$(normalize_cidr "$netip" "$prefix")" >> "$chunk_file"
  fi

done < "$input_file"

# Deduplicate + sort outputs
dedupe_and_versionsort_ips "$bcast_file"
dedupe_and_sort_cidrs      "$chunk_file"

echo "Wrote: $bcast_file"
echo "Wrote: $chunk_file"
