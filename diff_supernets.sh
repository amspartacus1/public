#!/usr/bin/env bash
# diff_supernets.sh
# Find IPs present in FILE2 but NOT in FILE1, aggregate to supernets,
# and (optionally) split results to a target mask.
# Portable: Bash 4+; uses only basic awk (no bitwise funcs).

set -euo pipefail
LC_ALL=C

usage() {
  cat <<'USAGE'
Usage:
  diff_supernets.sh [-m NETMASK|PREFIX] FILE1 FILE2

Inputs (required):
  FILE1, FILE2 : Text files with one subnet per line, either:
                 - CIDR notation:            10.0.0.0/24
                 - "network mask" notation:  10.0.0.0 255.255.255.0
                 Blank lines and lines starting with '#' are ignored.

Options:
  -m NETMASK   Split final output supernets into smaller subnets of this size.
               Accepts dotted mask (e.g., 255.255.255.192) or prefix (e.g., 26).

Output:
  A new file in the current directory named:
    $(basename FILE2)_NoOverlap_$(basename FILE1)
  containing CIDR blocks (one per line) that cover all IPs present in FILE2
  but not present in FILE1. If -m is given, results are split to that mask.

Notes:
  - IPv4 only. Non-contiguous masks are rejected.
  - Input subnets are normalized and overlaps/duplicates are handled.
USAGE
}

# ---------------- IPv4 helpers (pure Bash) ----------------

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
  if (( p==0 )); then echo 0; else echo $(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF )); fi
}

mask2prefix() {
  local mask=$1 m int p
  int=$(ip2int "$mask") || return 1
  for (( p=0; p<=32; p++ )); do
    m=$(prefix2mask_int "$p")
    if (( m == int )); then echo "$p"; return 0; fi
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

parse_line_to_netprefix() {
  local line=$1 ip prefix mask token1 token2
  if [[ $line =~ ^[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]{1,2})[[:space:]]*$ ]]; then
    ip="${BASH_REMATCH[1]}"; prefix="${BASH_REMATCH[2]}"
    (( prefix>=0 && prefix<=32 )) || return 1
    token1=$(normalize_cidr "$ip" "$prefix") || return 1
    echo "${token1%/*} ${token1#*/}"
    return 0
  fi
  read -r token1 token2 <<<"$line" || true
  if [[ -n ${token1:-} && -n ${token2:-} ]]; then
    ip="$token1"; mask="$token2"
    prefix=$(mask2prefix "$mask") || return 1
    token1=$(normalize_cidr "$ip" "$prefix") || return 1
    echo "${token1%/*} ${token1#*/}"
    return 0
  fi
  return 1
}

cidr_to_range() {
  # echo "start_int end_int" for a/b
  local ip=$1 p=$2 ipi mask net bcast
  ipi=$(ip2int "$ip") || return 1
  mask=$(prefix2mask_int "$p") || return 1
  net=$(( ipi & mask ))
  bcast=$(( net | (~mask & 0xFFFFFFFF) ))
  echo "$net $bcast"
}

# ---------------- Sorting/dedupe helpers ----------------

dedupe_sort_cidrs() {
  local f=$1
  if sort -V -u "$f" > "$f.tmp" 2>/dev/null; then
    mv "$f.tmp" "$f"
  else
    awk -F'[./]' 'NF==5 { printf "%03d.%03d.%03d.%03d/%03d|%s\n", $1,$2,$3,$4,$5,$0 }' "$f" \
      | sort -u | cut -d'|' -f2- > "$f.tmp"
    mv "$f.tmp" "$f"
  fi
}

# ---------------- Interval ops (pure Bash / simple awk) ----------------

cidrfile_to_intervals() {
  # $1 infile of CIDRs -> stdout "start end" (unsorted)
  local ip p s e
  while IFS=/ read -r ip p; do
    [[ -z ${ip:-} ]] && continue
    read -r s e < <(cidr_to_range "$ip" "$p")
    echo "$s $e"
  done < "$1"
}

merge_intervals_file() {
  # $1 intervals "start end" unsorted; $2 outfile merged
  sort -n -k1,1 "$1" | awk '
    NR==1 { s=$1; e=$2; next }
    {
      if ($1 <= e+1) { if ($2>e) e=$2 }
      else { print s, e; s=$1; e=$2 }
    }
    END { if (NR) print s, e }' > "$2"
}

diff_intervals_files() {
  # A \ B -> $3; A=$1 (merged/sorted); B=$2 (merged/sorted)
  # Efficient two-pointer numeric diff in awk (no bitwise).
  awk '
    NR==FNR { bs[++n]=$1; be[n]=$2; next }  # load B
    {
      s=$1; e=$2; i=1
      while (i<=n && be[i] < s) i++
      cur=s
      while (i<=n && bs[i] <= e) {
        if (be[i] < cur) { i++; continue }
        if (bs[i] > cur) { print cur, bs[i]-1 }
        if (be[i]+1 > cur) { cur = be[i]+1 }
        i++
      }
      if (cur <= e) print cur, e
    }' "$2" "$1" > "$3"
}

# ---------------- Range -> CIDR cover (pure Bash) ----------------

log2_pow2() { local n=$1 l=0; while (( n>1 )); do n=$((n>>1)); ((l++)); done; echo "$l"; }
largest_pow2_leq() { local n=$1 s=1; while (( (s<<1) <= n )); do s=$((s<<1)); done; echo "$s"; }
align_block_size() { local cur=$1 s=1; while (( (cur % (s<<1)) == 0 && s < (1<<31) )); do s=$((s<<1)); done; echo "$s"; }

cover_intervals_with_cidrs() {
  # $1 in: "start end"; stdout: CIDRs covering them
  local start end cur rem a b size lg p
  while read -r start end; do
    [[ -z ${start:-} ]] && continue
    cur=$start
    while (( cur <= end )); do
      rem=$(( end - cur + 1 ))
      a=$(align_block_size "$cur")
      b=$(largest_pow2_leq "$rem")
      size=$(( a < b ? a : b ))
      lg=$(log2_pow2 "$size")
      p=$(( 32 - lg ))
      echo "$(int2ip "$cur")/$p"
      cur=$(( cur + size ))
    done
  done < "$1"
}

# ---------------- CIDR summarization (supernetting; pure Bash) ----------------

summarize_cidrs_file() {
  # $1 infile CIDRs (any order), $2 outfile summarized
  local tmp sorted
  tmp=$(mktemp); sorted=$(mktemp)
  cp "$1" "$tmp"
  dedupe_sort_cidrs "$tmp"   # in-place

  local changed pass_in pass_out
  pass_in="$tmp"
  pass_out=$(mktemp)

  while :; do
    : > "$pass_out"
    changed=0
    mapfile -t lines < "$pass_in"
    local i=0 len=${#lines[@]}
    while (( i < len )); do
      local l1=${lines[i]}
      if (( i+1 < len )); then
        local l2=${lines[i+1]}
        local ip1=${l1%/*}; local p1=${l1#*/}
        local ip2=${l2%/*}; local p2=${l2#*/}
        if [[ $p1 == "$p2" ]]; then
          local n1 n2 size
          n1=$(ip2int "$ip1"); n2=$(ip2int "$ip2")
          size=$(( 1 << (32 - p1) ))
          if (( n2 == n1 + size )) && (( (n1 % (2*size)) == 0 )); then
            echo "$(int2ip "$n1")/$((p1-1))" >> "$pass_out"
            changed=1
            i=$(( i+2 ))
            continue
          fi
        fi
      fi
      echo "$l1" >> "$pass_out"
      i=$(( i+1 ))
    done
    # prepare for next pass
    mv "$pass_out" "$sorted"
    dedupe_sort_cidrs "$sorted"
    if cmp -s "$sorted" "$pass_in"; then
      break
    else
      changed=1
      mv "$sorted" "$pass_in"
      pass_out=$(mktemp)
    fi
  done
  mv "$sorted" "$2"
  rm -f "$tmp" "$pass_in" "$pass_out" 2>/dev/null || true
}

# ---------------- Optional split ----------------

split_cidr_to_prefix() {
  local netip=$1 cur_p=$2 tgt_p=$3
  if (( tgt_p <= cur_p )); then
    echo "$(int2ip "$netip")/$cur_p"
    return
  fi
  local blocks=$((1 << (tgt_p - cur_p)))
  local step=$((1 << (32 - tgt_p)))
  local i sub
  for (( i=0; i<blocks; i++ )); do
    sub=$(( netip + i*step ))
    echo "$(int2ip "$sub")/$tgt_p"
  done
}

# ---------------- CLI parsing ----------------

target_prefix=""
while getopts ":m:h" opt; do
  case "$opt" in
    m)
      if [[ $OPTARG =~ ^[0-9]{1,2}$ ]]; then
        (( OPTARG>=0 && OPTARG<=32 )) || { echo "Error: invalid prefix $OPTARG" >&2; exit 2; }
        target_prefix="$OPTARG"
      else
        target_prefix="$(mask2prefix "$OPTARG")" || { echo "Error: invalid netmask $OPTARG" >&2; exit 2; }
      fi
      ;;
    h) usage; exit 0 ;;
    \?) echo "Error: Invalid option -$OPTARG" >&2; usage; exit 2 ;;
    :)  echo "Error: Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))

if (( $# != 2 )); then
  echo "Error: exactly two input files are required." >&2
  usage
  exit 2
fi

f1="$1"; f2="$2"
[[ -r "$f1" && -r "$f2" ]] || { echo "Error: cannot read one or both input files." >&2; exit 2; }

out_file="$(basename "$f2")_NoOverlap_$(basename "$f1")"

# ---------------- Work files ----------------
t_dir="$(mktemp -d)"
trap 'rm -rf "$t_dir"' EXIT

f1_cidrs="$t_dir/f1.cidrs"
f2_cidrs="$t_dir/f2.cidrs"
f1_union="$t_dir/f1.union"
f2_union="$t_dir/f2.union"
diff_ints="$t_dir/diff.ints"
diff_cidrs="$t_dir/diff.cidrs"
summ_cidrs="$t_dir/summ.cidrs"
final_cidrs="$t_dir/final.cidrs"

: > "$f1_cidrs"; : > "$f2_cidrs"

# Normalize inputs to CIDR
while IFS= read -r raw || [[ -n "$raw" ]]; do
  line="${raw%$'\r'}"
  [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
  if parsed=$(parse_line_to_netprefix "$line"); then
    read -r nip pre <<<"$parsed"
    echo "$(normalize_cidr "$nip" "$pre")" >> "$f1_cidrs"
  else
    echo "Warning: skipping invalid line in $f1: $line" >&2
  fi
done < "$f1"

while IFS= read -r raw || [[ -n "$raw" ]]; do
  line="${raw%$'\r'}"
  [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
  if parsed=$(parse_line_to_netprefix "$line"); then
    read -r nip pre <<<"$parsed"
    echo "$(normalize_cidr "$nip" "$pre")" >> "$f2_cidrs"
  else
    echo "Warning: skipping invalid line in $f2: $line" >&2
  fi
done < "$f2"

# Intervals & unions (merged)
cidrfile_to_intervals "$f1_cidrs" > "$t_dir/f1.ints"
cidrfile_to_intervals "$f2_cidrs" > "$t_dir/f2.ints"
merge_intervals_file "$t_dir/f1.ints" "$f1_union"
merge_intervals_file "$t_dir/f2.ints" "$f2_union"

# difference: FILE2 \ FILE1
diff_intervals_files "$f2_union" "$f1_union" "$diff_ints"

# Cover gaps with minimal CIDRs
cover_intervals_with_cidrs "$diff_ints" > "$diff_cidrs"

# Summarize/supernet
summarize_cidrs_file "$diff_cidrs" "$summ_cidrs"

# Optional split to -m
if [[ -n "$target_prefix" ]]; then
  : > "$final_cidrs"
  while IFS=/ read -r ip pfx; do
    [[ -z ${ip:-} ]] && continue
    net_int=$(ip2int "$ip")
    split_cidr_to_prefix "$net_int" "$pfx" "$target_prefix"
  done < "$summ_cidrs" >> "$final_cidrs"
else
  cp "$summ_cidrs" "$final_cidrs"
fi

# Final sort/dedupe (stable)
dedupe_sort_cidrs "$final_cidrs"

# Always produce an output file (may be empty if no gaps)
cp "$final_cidrs" "./$out_file"
echo "Wrote: ./$out_file"
