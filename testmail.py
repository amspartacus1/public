#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Email Spoofing DNS Posture Checker
(Live DNS OR RFC1035 Zone File • Batch • CSV/MD/JSON • Quiet/Verbose • Risk
 • Common/CLI/File DKIM selectors • Live DKIM prints • Progress)
-----------------------------------------------------------------------------

NEW
---
• --zone-file ZONE [--zone-origin ORIGIN]
    Evaluate records from a local RFC1035/BIND zone file (offline).
    - TXT/MX/A/AAAA/PTR/TLSA/DS lookups are served from the zone.
    - Wildcard MX detection inspects "*" nodes in-zone (no synthesized answers).
    - MTA-STS HTTP fetch is skipped (marked INCONCLUSIVE); TXT checks still run.
    - Useful for CI, change reviews, or pre-DNS-publish posture checks.

Examples
--------
# Live DNS as before:
  python3 mail_dns_audit.py example.com --check-common-dkim --progress

# Offline from a zone file:
  python3 mail_dns_audit.py example.com \
    --zone-file ./db.example.com \
    --zone-origin example.com.

# Batch + selectors from file + common + CSV:
  python3 mail_dns_audit.py --domains-file doms.txt \
    --dkim-selectors-file selectors.txt \
    --check-common-dkim --csv out.csv --md out.md --json

Notes
-----
- Zone mode requires dnspython to parse RFC1035 files; origin is needed if
  the file uses relative names (typical for BIND). If not provided, we try
  to infer origin from SOA.
- In zone mode, wildcard MX detection checks for any node whose leftmost
  label is "*". That mirrors common BIND usage (*.example.com.). It does not
  synthesize wildcard answers.
"""

import argparse
import csv
import json
import random
import re
import string
import sys
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional, Set, Callable

import idna
import requests
import dns.resolver
import dns.reversename
import dns.zone
import dns.name
import dns.rdatatype

# ---------- Output model ----------

@dataclass
class CheckResult:
    domain: str
    name: str
    description: str
    status: str       # PASS / FAIL / INCONCLUSIVE
    details: str
    risk: str         # HIGH / MEDIUM / LOW / NONE / UNKNOWN

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"

# ---------- Utility: normalization ----------

def normalize_domain(d: str) -> str:
    d = d.strip().rstrip('.')
    try:
        return idna.decode(idna.encode(d))
    except idna.IDNAError:
        return d

def to_alabel(d: str) -> str:
    try:
        return idna.encode(d).decode()
    except idna.IDNAError:
        return d

# ---------- Progress utilities ----------

def progress_enabled(force: bool, total: int, threshold: int) -> bool:
    return bool(force or (total >= max(1, threshold)))

def progress_update(current: int, total: int, prefix: str = "DKIM selectors") -> None:
    sys.stderr.write(f"\r[progress] {prefix}: {current}/{total}")
    sys.stderr.flush()

def progress_done() -> None:
    sys.stderr.write("\n")
    sys.stderr.flush()

# ---------- Backends: Live DNS vs Zone File ----------

class DNSBackend:
    """Abstract backend API."""
    def txt(self, name: str) -> List[str]: ...
    def mx(self, name: str) -> List[Tuple[int, str]]: ...
    def addrs(self, name: str) -> List[str]: ...
    def ptr(self, ip: str) -> List[str]: ...
    def tlsa(self, host: str, port: int = 25) -> List[str]: ...
    def ds(self, name: str) -> List[str]: ...
    def has_wildcard_mx_under(self, zone_apex: str) -> bool: ...

class LiveDNS(DNSBackend):
    """Backend that uses the system’s resolver (live DNS)."""
    def __init__(self, timeout: float):
        r = dns.resolver.Resolver(configure=True)
        r.timeout = timeout
        r.lifetime = timeout
        self.r = r

    def _res(self, name: str, rdtype: str):
        try: return self.r.resolve(name, rdtype)
        except Exception: return []

    def txt(self, name: str) -> List[str]:
        out = []
        for rr in self._res(name, 'TXT'):
            try:
                chunks = [c.decode() if isinstance(c, (bytes, bytearray)) else c for c in rr.strings]
                out.append(''.join(chunks))
            except AttributeError:
                out.append(str(rr))
        return out

    def mx(self, name: str) -> List[Tuple[int, str]]:
        out = []
        for rr in self._res(name, 'MX'):
            out.append((int(rr.preference), str(rr.exchange).rstrip('.')))
        return sorted(out, key=lambda x: x[0])

    def addrs(self, name: str) -> List[str]:
        addrs = []
        for t in ('A', 'AAAA'):
            for rr in self._res(name, t):
                addrs.append(str(rr))
        return addrs

    def ptr(self, ip: str) -> List[str]:
        try:
            rev = dns.reversename.from_address(ip)
            answers = self._res(str(rev), 'PTR')
            return [str(r).rstrip('.') for r in answers]
        except Exception:
            return []

    def tlsa(self, host: str, port: int = 25) -> List[str]:
        name = f"_{port}._tcp.{host}."
        return [str(r) for r in self._res(name, 'TLSA')]

    def ds(self, name: str) -> List[str]:
        return [str(r) for r in self._res(name, 'DS')]

    def has_wildcard_mx_under(self, zone_apex: str) -> bool:
        # Live DNS: we can just probe a random label (handled in the check itself)
        return False  # not used; wildcard detected via random probe in live mode

class ZoneDNS(DNSBackend):
    """Backend that answers from a parsed RFC1035/BIND zone file (offline)."""
    def __init__(self, zone: dns.zone.Zone):
        self.zone = zone
        self.origin: dns.name.Name = zone.origin

    def _abs(self, qname: str) -> dns.name.Name:
        # Make absolute against origin
        n = dns.name.from_text(qname)
        return n if n.is_absolute() else n.relativize(self.origin).concatenate(self.origin)

    def _rdataset(self, qname: str, rdtype: dns.rdatatype.RdataType):
        try:
            node = self.zone.get_node(self._abs(qname), create=False)
            if node is None:
                return None
            for rdataset in node.rdatasets:
                if rdataset.rdtype == rdtype:
                    return rdataset
        except Exception:
            return None
        return None

    def txt(self, name: str) -> List[str]:
        rd = self._rdataset(name, dns.rdatatype.TXT)
        out: List[str] = []
        if rd:
            for r in rd:
                # dnspython stores TXT chunks in r.strings (bytes) or .to_text()
                if hasattr(r, "strings"):
                    chunks = [c.decode() if isinstance(c, (bytes, bytearray)) else c for c in r.strings]
                    out.append(''.join(chunks))
                else:
                    # r.to_text() returns quoted chunks; strip quotes heuristically
                    t = r.to_text()
                    out.append(t.strip('"'))
        return out

    def mx(self, name: str) -> List[Tuple[int, str]]:
        rd = self._rdataset(name, dns.rdatatype.MX)
        out: List[Tuple[int, str]] = []
        if rd:
            for r in rd:
                out.append((int(r.preference), r.exchange.to_text().rstrip('.')))
        return sorted(out, key=lambda x: x[0])

    def addrs(self, name: str) -> List[str]:
        out: List[str] = []
        for rt in (dns.rdatatype.A, dns.rdatatype.AAAA):
            rd = self._rdataset(name, rt)
            if rd:
                for r in rd:
                    out.append(r.address)
        return out

    def ptr(self, ip: str) -> List[str]:
        try:
            rev = dns.reversename.from_address(ip)
        except Exception:
            return []
        rd = self._rdataset(str(rev), dns.rdatatype.PTR)
        out: List[str] = []
        if rd:
            for r in rd:
                out.append(r.target.to_text().rstrip('.'))
        return out

    def tlsa(self, host: str, port: int = 25) -> List[str]:
        name = f"_{port}._tcp.{host}."
        rd = self._rdataset(name, dns.rdatatype.TLSA)
        return [r.to_text() for r in rd] if rd else []

    def ds(self, name: str) -> List[str]:
        rd = self._rdataset(name, dns.rdatatype.DS)
        return [r.to_text() for r in rd] if rd else []

    def has_wildcard_mx_under(self, zone_apex: str) -> bool:
        """
        Check for explicit wildcard MX nodes like *.example.com.
        We scan zone nodes for any whose leftmost label == '*'
        and that have an MX rdataset.
        """
        for (nr, node) in self.zone.nodes.items():
            # nr is a dns.name.Name relative to origin
            if len(nr.labels) >= 1 and nr.labels[0] == b'*':
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.MX:
                        return True
        return False

# ---------- SPF helpers (parse / lookup counting) ----------

SPF_RE = re.compile(r'^\s*v=spf1\s+(?P<body>.+)$', re.IGNORECASE)

def tokenize_spf(body: str) -> List[str]:
    return body.strip().split()

def spf_mechanisms(tokens: List[str]) -> List[str]:
    mechs = []
    for t in tokens:
        if '=' in t and not any(t.startswith(x) for x in ('include:', 'exists:')):
            continue
        mechs.append(t)
    return mechs

def extract_spf_policy(tokens: List[str]) -> Optional[str]:
    for t in reversed(tokens):
        if t.endswith('all'):
            return t
    return None

def get_spf_record(backend: DNSBackend, domain: str) -> Tuple[List[str], List[str]]:
    txts = backend.txt(domain)
    spf_records = [t for t in txts if t.lower().startswith('v=spf1')]
    return spf_records, txts

def count_spf_lookups(backend: DNSBackend,
                      domain: str,
                      spf: str,
                      budget: int = 10) -> Tuple[int, Set[str], List[str], bool]:
    """
    RFC 7208 lookup counters (include,a,mx,ptr,exists,redirect). We follow
    include/redirect recursively within the same backend.
    """
    visited: Set[str] = set()
    errors: List[str] = []
    exceeded = False
    total = 0

    def _expand(label: str, level: int = 0):
        nonlocal total, exceeded
        if total > budget:
            exceeded = True; return
        if level > 20:
            errors.append(f"SPF recursion too deep at {label}"); return
        try:
            spf_rrs, _ = get_spf_record(backend, label)
        except Exception as e:
            errors.append(f"Lookup error at {label}: {e}"); return
        if not spf_rrs:
            errors.append(f"No SPF record found during include/redirect expansion at {label}"); return
        m = SPF_RE.match(spf_rrs[0])
        if not m:
            errors.append(f"Malformed SPF at {label}"); return
        tokens = tokenize_spf(m.group('body'))
        for tok in tokens:
            if tok.startswith('redirect='):
                tgt = tok.split('=', 1)[1]
                total += 1
                if total > budget: exceeded = True; return
                if tgt not in visited:
                    visited.add(tgt); _expand(tgt, level + 1)
                continue
            if tok.startswith('include:'):
                tgt = tok.split(':', 1)[1]
                total += 1
                if total > budget: exceeded = True; return
                if tgt not in visited:
                    visited.add(tgt); _expand(tgt, level + 1)
            elif tok == 'mx' or tok.startswith('mx:'):
                total += 1
            elif tok == 'a' or tok.startswith('a:'):
                total += 1
            elif tok.startswith('exists:'):
                total += 1
            elif tok.startswith('ptr'):
                total += 1
            if total > budget: exceeded = True; return

    _expand(domain, 0)
    return total, visited, errors, exceeded

# ---------- DKIM: common selectors & risk ----------

COMMON_DKIM_SELECTORS: List[str] = [
    "default", "dkim", "dkim1", "dkim2", "selector", "selector1", "selector2",
    "s1", "s2", "k1", "k2", "mail", "mx", "smtp", "mta", "email",
    "noreply", "news", "newsletter", "marketing", "mktg", "transactional",
    "google", "google1", "google2",
    "zoho", "zoho1", "zoho2",
    "mandrill", "mailchimp",
    "sendgrid",
    "sparkpost",
    "postmark", "pm",
    "mailgun", "mg", "mg1", "mg2",
]

def assess_risk(name: str, status: str, details: str) -> str:
    if status == PASS:
        return "NONE"
    if status == INCONCLUSIVE:
        return "UNKNOWN"
    n = name.lower(); d = details.lower()
    if n.startswith("dmarc: published"): return "HIGH"
    if "dmarc: enforcement" in n: return "HIGH" if ("p=none" in d or "not enforcing" in d) else "NONE"
    if "dmarc: subdomain policy" in n: return "MEDIUM"
    if "dmarc: strict alignment" in n: return "LOW"
    if "dmarc: aggregate reporting" in n: return "LOW"
    if n.startswith("spf: published"): return "HIGH"
    if "spf: single txt only" in n: return "MEDIUM"
    if "spf: syntax" in n: return "HIGH"
    if "spf: lookup count" in n: return "MEDIUM" if "exceed" in d else "NONE"
    if "spf: explicit terminal policy" in n: return "MEDIUM"
    if "spf: strict terminal policy" in n: return "MEDIUM"
    if "spf: risky mechanisms avoided" in n: return "MEDIUM"
    if n.startswith("dkim: selectors published"): return "MEDIUM" if "no dkim key" in d else "NONE"
    if n.startswith("dkim: _domainkey policy txt"): return "LOW" if status == FAIL else ("UNKNOWN" if status == INCONCLUSIVE else "NONE")
    if n.startswith("mx: explicit receivers"): return "MEDIUM" if "fall back" in d else "NONE"
    if "mx: wildcard acceptance" in n: return "MEDIUM"
    if "mx: ptr/rdns sanity" in n: return "LOW" if ("no ptr" in d or "not matching" in d) else "NONE"
    if n.startswith("dnssec:"): return "MEDIUM"
    if n.startswith("mta-sts:"): return "MEDIUM"
    if n.startswith("tls-rpt:"): return "LOW"
    if n.startswith("dane:"): return "LOW"
    return "LOW"

def R(domain: str, name: str, desc: str, status: str, details: str) -> CheckResult:
    return CheckResult(domain, name, desc, status, details, assess_risk(name, status, details))

# ---------- Checks (SPF / DMARC / DKIM / MX / DNSSEC / MTA-STS+TLS-RPT / DANE) ----------

def check_spf(backend: DNSBackend, domain: str) -> List[CheckResult]:
    desc = "SPF presence/safety: single TXT, ≤10 lookups, terminal policy, avoid risky mechanisms."
    results: List[CheckResult] = []
    spf_rrs, _ = get_spf_record(backend, domain)

    if not spf_rrs:
        results.append(R(domain, "SPF: published", desc, FAIL,
                         "No SPF record (TXT starting with 'v=spf1') found."))
        return results

    if len(spf_rrs) > 1:
        results.append(R(domain, "SPF: single TXT only", desc, FAIL,
                         f"Multiple SPF TXT records found ({len(spf_rrs)}). Records: {spf_rrs}"))
    else:
        results.append(R(domain, "SPF: single TXT only", desc, PASS,
                         f"One SPF TXT record found: {spf_rrs[0]}"))

    match = SPF_RE.match(spf_rrs[0])
    if not match:
        results.append(R(domain, "SPF: syntax", desc, FAIL, f"Malformed SPF record: {spf_rrs[0]}"))
        return results

    body = match.group('body')
    tokens = tokenize_spf(body)
    mechs = spf_mechanisms(tokens)

    total, visited, errs, exceeded = count_spf_lookups(backend, domain, spf_rrs[0])
    if exceeded:
        results.append(R(domain, "SPF: lookup count ≤ 10", desc, FAIL,
                         f"Estimated lookups exceed 10 (≈{total}). Errors: {errs}"))
    else:
        results.append(R(domain, "SPF: lookup count ≤ 10", desc, PASS,
                         f"Estimated lookups within budget (≈{total}). Includes/redirects: {sorted(list(visited))}"))

    policy = extract_spf_policy(tokens)
    if policy is None:
        results.append(R(domain, "SPF: explicit terminal policy", desc, FAIL,
                         "No terminal 'all' mechanism (-all/~all/?all/+all)."))
    else:
        if policy.startswith('-all'):
            results.append(R(domain, "SPF: strict terminal policy (-all)", desc, PASS,
                             f"Terminal policy is '{policy}'."))
        else:
            results.append(R(domain, "SPF: strict terminal policy (-all)", desc, FAIL,
                             f"Terminal policy is '{policy}'. Prefer '-all' once validated."))

    risky = [t for t in mechs if t.startswith('ptr') or t.startswith('exists:') or t == '+all']
    if risky:
        results.append(R(domain, "SPF: risky mechanisms avoided", desc, FAIL,
                         f"Risky mechanisms detected: {', '.join(risky)}. Avoid 'ptr', broad 'exists', '+all'."))
    else:
        results.append(R(domain, "SPF: risky mechanisms avoided", desc, PASS,
                         "No 'ptr', broad 'exists', or '+all' detected."))
    return results

def parse_taglist(txt: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in txt.split(';'):
        part = part.strip()
        if not part: continue
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    return tags

def check_dmarc(backend: DNSBackend, domain: str) -> List[CheckResult]:
    desc = "DMARC presence, enforcement, alignment strictness, and reporting."
    results: List[CheckResult] = []
    label = f"_dmarc.{domain}"
    txts = backend.txt(label)
    dmarc = [t for t in txts if t.lower().startswith('v=dmarc1')]

    if not dmarc:
        results.append(R(domain, "DMARC: published", desc, FAIL, f"No DMARC record at {label}."))
        return results

    rec = dmarc[0]
    tags = parse_taglist(rec)

    results.append(R(domain, "DMARC: published", desc, PASS, f"Record: {rec}"))

    p = tags.get('p', '').lower()
    if p in ('reject', 'quarantine'):
        results.append(R(domain, "DMARC: enforcement (p=)", desc, PASS, f"p={p}."))
    elif p == 'none':
        results.append(R(domain, "DMARC: enforcement (p=)", desc, FAIL, "p=none (monitor only)."))
    else:
        results.append(R(domain, "DMARC: enforcement (p=)", desc, FAIL, f"p={p or '(missing)'} not enforcing."))

    sp = tags.get('sp', '').lower()
    if sp in ('reject', 'quarantine'):
        results.append(R(domain, "DMARC: subdomain policy (sp=)", desc, PASS, f"sp={sp}."))
    else:
        results.append(R(domain, "DMARC: subdomain policy (sp=)", desc, FAIL,
                         f"sp={(sp or 'not set')} (subdomains may be unprotected)."))

    adkim = tags.get('adkim', 'r').lower()
    aspf = tags.get('aspf', 'r').lower()
    if adkim == 's' and aspf == 's':
        results.append(R(domain, "DMARC: strict alignment (adkim/aspf)", desc, PASS, "adkim=s; aspf=s"))
    else:
        results.append(R(domain, "DMARC: strict alignment (adkim/aspf)", desc, FAIL,
                         f"adkim={adkim}; aspf={aspf} (strict preferred)."))

    rua = tags.get('rua', '')
    if rua and 'mailto:' in rua:
        results.append(R(domain, "DMARC: aggregate reporting (rua)", desc, PASS, f"rua={rua}"))
    else:
        results.append(R(domain, "DMARC: aggregate reporting (rua)", desc, FAIL,
                         "rua missing or malformed."))
    return results

def check_dkim(backend: DNSBackend,
               domain: str,
               selectors: List[str],
               common_mode: bool,
               live_prints: bool,
               prog_active: bool,
               prog_cb: Optional[Callable[[int, int], None]]) -> List[CheckResult]:
    desc = "DKIM selector publication and optional _domainkey policy TXT."
    results: List[CheckResult] = []

    pol_label = f"_domainkey.{domain}"
    pol = backend.txt(pol_label)
    if pol:
        results.append(R(domain, "DKIM: _domainkey policy TXT", desc, PASS,
                         f"Policy TXT found at {pol_label}: {pol}"))
    else:
        results.append(R(domain, "DKIM: _domainkey policy TXT", desc, INCONCLUSIVE,
                         f"No TXT at {pol_label} (optional)."))

    discovered = []
    tested_any = False
    total = len(selectors); current = 0

    for sel in selectors:
        tested_any = True
        label = f"{sel}._domainkey.{domain}"
        txts = backend.txt(label)

        current += 1
        if prog_active and prog_cb is not None:
            prog_cb(current, total)

        if txts:
            for t in txts:
                if 'p=' in t:
                    discovered.append((sel, t))
                    if live_prints:
                        print(f"[DKIM] {domain}: FOUND selector '{sel}'", flush=True)
                    break

    if prog_active:
        progress_done()

    if discovered:
        details = "; ".join([f"{sel} -> {txt[:120]}{'...' if len(txt)>120 else ''}" for sel, txt in discovered])
        results.append(R(domain, "DKIM: selectors published (tested)", desc, PASS,
                         f"Keys found: {details}"))
    else:
        if tested_any:
            origin = " (tested set: common)" if common_mode else ""
            results.append(R(domain, "DKIM: selectors published (tested)", desc, FAIL,
                             f"No DKIM key TXT for selectors: {', '.join(selectors)}{origin}"))
        else:
            results.append(R(domain, "DKIM: selectors published (tested)", desc, INCONCLUSIVE,
                             "No selectors specified. Use --dkim-selector/--dkim-selectors-file and/or --check-common-dkim."))
    return results

def random_label(n: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))

def check_mx_hygiene(backend: DNSBackend, domain: str, zone_backend: Optional[ZoneDNS]) -> List[CheckResult]:
    desc = "MX presence, wildcard heuristic, and PTR sanity."
    results: List[CheckResult] = []

    mx = backend.mx(domain)
    if not mx:
        addrs = backend.addrs(domain)
        if addrs:
            results.append(R(domain, "MX: explicit receivers", desc, FAIL,
                             f"No MX; SMTP may fall back to A/AAAA: {', '.join(addrs)}"))
        else:
            results.append(R(domain, "MX: explicit receivers", desc, PASS,
                             "No MX and no A/AAAA → domain likely does not accept mail."))
    else:
        results.append(R(domain, "MX: explicit receivers", desc, PASS,
                         f"MX present: {', '.join([f'{p} {h}' for p, h in mx])}"))

    # Wildcard detection
    if isinstance(backend, LiveDNS):
        sub = f"{random_label()}.{domain}"
        sub_mx = backend.mx(sub)
        if sub_mx:
            results.append(R(domain, "MX: wildcard acceptance (heuristic)", desc, FAIL,
                             f"Random subdomain {sub} returned MX: {', '.join([f'{p} {h}' for p, h in sub_mx])}"))
        else:
            results.append(R(domain, "MX: wildcard acceptance (heuristic)", desc, PASS,
                             f"No MX for random subdomain {sub}"))
    else:
        # Zone mode: inspect "*" nodes
        has_wc = zone_backend.has_wildcard_mx_under(domain) if zone_backend else False
        if has_wc:
            results.append(R(domain, "MX: wildcard acceptance (heuristic)", desc, FAIL,
                             "Wildcard MX record (*.domain) found in zone file."))
        else:
            results.append(R(domain, "MX: wildcard acceptance (heuristic)", desc, PASS,
                             "No wildcard MX found in zone file."))

    # PTR sanity for MX targets
    issues = []
    for _, host in mx:
        ips = backend.addrs(host)
        for ip in ips:
            ptrs = backend.ptr(ip)
            if not ptrs:
                issues.append(f"{host} ({ip}) has no PTR")
            else:
                parent = domain.split('.', 1)[-1]
                if not any(parent in p or host in p for p in ptrs):
                    issues.append(f"{host} ({ip}) PTR '{ptrs[0]}' not matching host/domain")
    if issues:
        results.append(R(domain, "MX: PTR/rDNS sanity", desc, FAIL, "; ".join(issues)))
    else:
        if mx:
            results.append(R(domain, "MX: PTR/rDNS sanity", desc, PASS,
                             "PTRs exist and appear sane for MX targets."))
    return results

def check_dnssec(backend: DNSBackend, domain: str) -> List[CheckResult]:
    desc = "DNSSEC delegation status (DS present)."
    ds = backend.ds(domain)
    if ds:
        return [R(domain, "DNSSEC: delegation signed (DS)", desc, PASS,
                  f"DS present: {', '.join(ds[:5])}{' ...' if len(ds)>5 else ''}")]
    else:
        return [R(domain, "DNSSEC: delegation signed (DS)", desc, FAIL,
                  "No DS records (zone likely unsigned).")]

def check_mtasts_tlsrpt(backend: DNSBackend, domain: str, timeout: float, offline: bool) -> List[CheckResult]:
    desc = "MTA-STS policy presence/mode and TLS-RPT reporting."
    results: List[CheckResult] = []

    label = f"_mta-sts.{domain}"
    mtasts = backend.txt(label)
    if mtasts:
        results.append(R(domain, "MTA-STS: TXT presence", desc, PASS,
                         f"{label} TXT: {mtasts}"))
        if offline:
            results.append(R(domain, "MTA-STS: policy retrieval", desc, INCONCLUSIVE,
                             "Offline/zone mode: HTTP policy fetch skipped."))
        else:
            try:
                url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                r = requests.get(url, timeout=timeout)
                if r.status_code == 200:
                    text = r.text.strip()
                    mode = None
                    for line in text.splitlines():
                        if line.lower().startswith('mode:'):
                            mode = line.split(':', 1)[1].strip().lower(); break
                    if mode == 'enforce':
                        results.append(R(domain, "MTA-STS: policy mode", desc, PASS, "mode=enforce"))
                    else:
                        results.append(R(domain, "MTA-STS: policy mode", desc, FAIL,
                                         f"mode={mode or 'unknown'} (prefer 'enforce')"))
                else:
                    results.append(R(domain, "MTA-STS: policy retrieval", desc, FAIL,
                                     f"HTTP {r.status_code} fetching policy"))
            except Exception as e:
                results.append(R(domain, "MTA-STS: policy retrieval", desc, FAIL,
                                 f"Error fetching policy: {e}"))
    else:
        results.append(R(domain, "MTA-STS: TXT presence", desc, FAIL,
                         f"No TXT at {label}"))

    rpt_label = f"_smtp._tls.{domain}"
    tlsrpt = backend.txt(rpt_label)
    if tlsrpt:
        if any('rua=' in t.lower() and 'mailto:' in t.lower() for t in tlsrpt):
            results.append(R(domain, "TLS-RPT: reporting address", desc, PASS,
                             f"{rpt_label} TXT with rua present"))
        else:
            results.append(R(domain, "TLS-RPT: reporting address", desc, FAIL,
                             f"{rpt_label} TXT present but missing valid rua=mailto"))
    else:
        results.append(R(domain, "TLS-RPT: reporting address", desc, FAIL,
                         f"No TXT at {rpt_label}"))
    return results

def check_dane(backend: DNSBackend, domain: str) -> List[CheckResult]:
    desc = "DANE TLSA records on MX hosts."
    results: List[CheckResult] = []
    mx = backend.mx(domain)
    if not mx:
        return [R(domain, "DANE: TLSA records on MX hosts", desc, INCONCLUSIVE,
                  "No MX records to evaluate.")]
    had_tlsa = False
    details = []
    for _, host in mx:
        tlsas = backend.tlsa(host, 25)
        if tlsas:
            had_tlsa = True
            details.append(f"{host}: {len(tlsas)} TLSA")
        else:
            details.append(f"{host}: no TLSA")
    if had_tlsa:
        results.append(R(domain, "DANE: TLSA records on MX hosts", desc, PASS,
                         "; ".join(details)))
    else:
        results.append(R(domain, "DANE: TLSA records on MX hosts", desc, FAIL,
                         "No TLSA on any MX host."))
    return results

# ---------- File helpers ----------

def read_list_file(path: str) -> List[str]:
    items: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            items.append(s)
    return items

def dedupe_preserve_order(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))

# ---------- Runner & Formatting ----------

def run_checks_for_domain(domain: str,
                          backend: DNSBackend,
                          zone_backend: Optional[ZoneDNS],
                          selectors: List[str],
                          timeout: float,
                          use_common_dkim: bool,
                          live_dkim_prints: bool,
                          prog_force: bool,
                          prog_threshold: int,
                          offline: bool) -> List[CheckResult]:
    """Execute the full suite for one domain with the chosen backend."""
    alabel_domain = to_alabel(normalize_domain(domain))
    total = len(selectors)
    prog_active = progress_enabled(prog_force, total, prog_threshold)
    prog_cb = (lambda cur, tot: progress_update(cur, tot, prefix=f"DKIM selectors ({alabel_domain})")) if prog_active else None

    results: List[CheckResult] = []
    results.extend(check_spf(backend, alabel_domain))
    results.extend(check_dmarc(backend, alabel_domain))
    results.extend(check_dkim(backend, alabel_domain, selectors, common_mode=use_common_dkim,
                              live_prints=live_dkim_prints, prog_active=prog_active, prog_cb=prog_cb))
    results.extend(check_mx_hygiene(backend, alabel_domain, zone_backend))
    results.extend(check_dnssec(backend, alabel_domain))
    results.extend(check_mtasts_tlsrpt(backend, alabel_domain, timeout, offline=offline))
    results.extend(check_dane(backend, alabel_domain))
    return results

def truncate_detail(detail: str, maxlen: int = 120) -> str:
    d = detail.strip().replace('\n', ' ')
    return d if len(d) <= maxlen else d[:maxlen - 1] + "…"

def print_table(results: List[CheckResult], quiet: bool):
    if not results:
        print("No results."); return
    by_domain: Dict[str, List[CheckResult]] = {}
    for r in results:
        by_domain.setdefault(r.domain, []).append(r)
    for domain, rows in by_domain.items():
        print(f"\n=== {domain} ===")
        headers = ["Check", "Description", "Status", "Risk", "Details"]
        widths = [28, 40, 10, 8, 70]
        def fmt_cell(text, width):
            text = str(text)
            return text.ljust(width) if len(text) <= width else text[:width-1] + "…"
        line = "-" * (sum(widths) + 9)
        print(line)
        print(f"| {fmt_cell(headers[0], widths[0])} | {fmt_cell(headers[1], widths[1])} | {fmt_cell(headers[2], widths[2])} | {fmt_cell(headers[3], widths[3])} | {fmt_cell(headers[4], widths[4])} |")
        print(line)
        for r in rows:
            details = truncate_detail(r.details) if quiet else r.details
            print(f"| {fmt_cell(r.name, widths[0])} | {fmt_cell(r.description, widths[1])} | {fmt_cell(r.status, widths[2])} | {fmt_cell(r.risk, widths[3])} | {fmt_cell(details, widths[4])} |")
        print(line)

def write_csv(path: str, results: List[CheckResult], quiet: bool):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "check", "description", "status", "risk", "details"])
        for r in results:
            details = truncate_detail(r.details) if quiet else r.details
            w.writerow([r.domain, r.name, r.description, r.status, r.risk, details])

def write_markdown(path: str, results: List[CheckResult], quiet: bool):
    by_domain: Dict[str, List[CheckResult]] = {}
    for r in results:
        by_domain.setdefault(r.domain, []).append(r)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Email Spoofing DNS Posture Report\n\n")
        for domain, rows in by_domain.items():
            f.write(f"## {domain}\n\n")
            f.write("| Check | Description | Status | Risk | Details |\n")
            f.write("|---|---|:---:|:---:|---|\n")
            for r in rows:
                details = truncate_detail(r.details) if quiet else r.details
                cells = [
                    r.name.replace("|", "\\|"),
                    r.description.replace("|", "\\|"),
                    r.status.replace("|", "\\|"),
                    r.risk.replace("|", "\\|"),
                    details.replace("|", "\\|"),
                ]
                f.write(f"| {cells[0]} | {cells[1]} | {cells[2]} | {cells[3]} | {cells[4]} |\n")
            f.write("\n")

# ---------- CLI ----------

def read_domains_from_file(path: str) -> List[str]:
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            out.append(s)
    return out

def cli():
    ap = argparse.ArgumentParser(
        description="Check DNS-centric misconfigurations enabling email spoofing (live DNS or RFC1035 zone)."
    )
    ap.add_argument("domains", nargs="*", help="Domain(s) to check (e.g., example.com)")
    ap.add_argument("--domains-file", help="File with one domain per line")

    # Zone-file (offline) mode
    ap.add_argument("--zone-file", help="RFC1035/BIND zone file to load and use for all lookups (offline).")
    ap.add_argument("--zone-origin", help="Zone origin (e.g., example.com.) if the zone file uses relative names.")

    # DKIM selectors
    ap.add_argument("--dkim-selector", action="append", default=[],
                    help="DKIM selector to test (e.g., tx1). May be specified multiple times.")
    ap.add_argument("--dkim-selectors-file",
                    help="Path to text file with DKIM selectors (one per line; '#' comments allowed).")
    ap.add_argument("--check-common-dkim", action="store_true",
                    help="Also test a curated list of common DKIM selectors across popular providers.")
    ap.add_argument("--list-common-dkim", action="store_true",
                    help="Print the curated common DKIM selector list and exit.")

    # LIVE prints + progress
    ap.add_argument("--no-live-dkim-prints", action="store_true",
                    help="Disable live STDOUT prints for each discovered DKIM selector.")
    ap.add_argument("--progress", action="store_true",
                    help="Force-enable progress indicator for DKIM selector scanning.")
    ap.add_argument("--progress-threshold", type=int, default=20,
                    help="Auto-enable progress when total selectors >= N (default: 20).")

    ap.add_argument("--timeout", type=float, default=3.0, help="DNS/HTTP timeout seconds (default: 3.0)")
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout (aggregate across all domains)")
    ap.add_argument("--csv", help="Write CSV to this path")
    ap.add_argument("--md", help="Write Markdown to this path")
    detail = ap.add_mutually_exclusive_group()
    detail.add_argument("--quiet", action="store_true", help="Short details (one-liners)")
    detail.add_argument("--verbose", action="store_true", help="Verbose details (default)")
    args = ap.parse_args()

    if args.list_common_dkim:
        print("# Common DKIM selector set")
        for sel in COMMON_DKIM_SELECTORS:
            print(sel)
        sys.exit(0)

    # --- Load zone first (if provided) ---
    zone_backend: Optional[ZoneDNS] = None
    offline = False
    if args.zone_file:
        try:
            if args.zone_origin:
                origin = dns.name.from_text(args.zone_origin)
                z = dns.zone.from_file(args.zone_file, origin=origin, relativize=False)
            else:
                z = dns.zone.from_file(args.zone_file, relativize=False)
            zone_backend = ZoneDNS(z)
            backend: DNSBackend = zone_backend
            offline = True
        except Exception as e:
            print(f"ERROR: Failed to load zone file: {e}")
            sys.exit(2)
    else:
        backend = LiveDNS(args.timeout)

    # --- Build domain list ---
    domains: List[str] = []
    if args.domains:
        domains.extend(args.domains)
    if args.domains_file:
        domains.extend(read_domains_from_file(args.domains_file))

    # If still empty and we have a zone, default to the zone apex (origin)
    if not domains and zone_backend is not None:
        domains = [zone_backend.origin.to_text().rstrip('.')]

    domains = [d for d in [normalize_domain(d) for d in domains] if d]

    # Only error if we have neither domains nor a zone file
    if not domains:
        print("No domains supplied. Provide one or more domains, --domains-file, or --zone-file.")
        sys.exit(2)

    # --- Build selector list (CLI ∪ file ∪ optional common), dedupe preserve order ---
    selectors_source: List[str] = []
    selectors_source.extend(args.dkim_selector or [])
    if args.dkim_selectors_file:
        try:
            selectors_source.extend(read_list_file(args.dkim_selectors_file))
        except FileNotFoundError:
            print(f"ERROR: DKIM selectors file not found: {args.dkim_selectors_file}")
            sys.exit(2)
    if args.check_common_dkim:
        selectors_source.extend(COMMON_DKIM_SELECTORS)
    selectors_final: List[str] = dedupe_preserve_order([s.strip() for s in selectors_source if s and s.strip()])

    live_dkim_prints = (not args.no_live_dkim_prints)

    # --- Run checks ---
    all_results: List[CheckResult] = []
    for d in domains:
        all_results.extend(
            run_checks_for_domain(
                d,
                backend=backend,
                zone_backend=zone_backend,
                selectors=selectors_final,
                timeout=args.timeout,
                use_common_dkim=args.check_common_dkim,
                live_dkim_prints=live_dkim_prints,
                prog_force=args.progress,
                prog_threshold=args.progress_threshold,
                offline=offline
            )
        )

    print_table(all_results, quiet=args.quiet)

    if args.json:
        payload = [
            {
                "domain": r.domain,
                "check": r.name,
                "description": r.description,
                "status": r.status,
                "risk": r.risk,
                "details": (truncate_detail(r.details) if args.quiet else r.details)
            } for r in all_results
        ]
        print(json.dumps(payload, indent=2))

    if args.csv:
        write_csv(args.csv, all_results, quiet=args.quiet)
        print(f"[+] Wrote CSV: {args.csv}")

    if args.md:
        write_markdown(args.md, all_results, quiet=args.quiet)
        print(f"[+] Wrote Markdown: {args.md}")

if __name__ == "__main__":
    cli()
