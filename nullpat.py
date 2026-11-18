#!/usr/bin/env python3
"""
NullPAT - the Null-Session Password Audit Tool
=================================================

A from-scratch, dependency-free reimplementation of DPAT
(https://github.com/clr2of8/DPAT) for correlating a cracked-password list
against an NTDS.dit dump and producing an audit-ready report.

NullPAT does not crack anything itself. It takes passwords you (or your
cracking rig) have already recovered through an authorized engagement and
turns them into the statistics an auditor actually needs: reuse, blank
passwords, legacy LM storage, privileged-account exposure, and password
hygiene trends.

Typical use:

    python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile

Built by Ahmed Hasan (@BudSec)
    LinkedIn : https://www.linkedin.com/in/budsec
    GitHub   : https://github.com/buddysecurity
    YouTube  : https://youtube.com/@BudSec

Author note: this tool handles cleartext passwords. Treat every report it
writes as client-confidential data -- encrypt it at rest, restrict who can
open it, and delete it once it has served its purpose in the engagement.
"""

from __future__ import annotations

import argparse
import base64
import collections
import csv
import datetime
import html
import io
import json
import os
import re
import sys
import time

VERSION = "1.1.0"

AUTHOR_NAME = "Ahmed Hasan"
AUTHOR_HANDLE = "@BudSec"
AUTHOR_LINKEDIN = "https://www.linkedin.com/in/budsec"
AUTHOR_GITHUB = "https://github.com/buddysecurity"
AUTHOR_YOUTUBE = "https://youtube.com/@BudSec"

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Brand palette (matches the user's house colors)
BLUE = (0x20, 0x43, 0x99)   # #204399
RED = (0xec, 0x1b, 0x3c)    # #ec1b3c
WHITE = (0xff, 0xff, 0xff)
INK = (0x16, 0x1c, 0x2e)
MUTED = (0x6b, 0x74, 0x8c)

DEFAULT_WEAK_PATTERNS = [
    (r"p[a@4]ssw[o0]rd\d*", "contains 'password'"),
    (r"welcome\d*", "contains 'welcome'"),
    (r"qwerty", "keyboard-walk pattern"),
    (r"123456", "sequential digits"),
    (r"letme[i1]n", "contains 'letmein'"),
    (r"admin\d*", "contains 'admin'"),
    (r"changeme\d*", "contains 'changeme'"),
    (r"(spring|summer|fall|autumn|winter)[\W_]?\d{0,4}", "season + year pattern"),
    (r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\W_]?\d{2,4}",
     "month + year pattern"),
]


# --------------------------------------------------------------------------
# Terminal color handling
# --------------------------------------------------------------------------

class Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, text, code):
        if not self.enabled:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def rgb(self, text, rgb, bold=False):
        if not self.enabled:
            return text
        r, g, b = rgb
        prefix = "1;" if bold else ""
        return f"\x1b[{prefix}38;2;{r};{g};{b}m{text}\x1b[0m"

    def bold(self, text):
        return self._wrap(text, "1")

    def dim(self, text):
        return self._wrap(text, "2")

    def ok(self, text):
        return self._wrap(text, "92")

    def warn(self, text):
        return self._wrap(text, "93")

    def bad(self, text):
        return self._wrap(text, "91")

    def info(self, text):
        return self.rgb(text, BLUE, bold=True)

    def accent(self, text):
        return self.rgb(text, RED, bold=True)


def color_enabled(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


# --------------------------------------------------------------------------
# Banner (zero-dependency 5x7 block font, just the glyphs NullPAT needs)
# --------------------------------------------------------------------------

_FONT_5X7 = {
    "N": ["X...X", "XX..X", "X.X.X", "X.X.X", "X..XX", "X...X", "X...X"],
    "U": ["X...X", "X...X", "X...X", "X...X", "X...X", "X...X", ".XXX."],
    "L": ["X....", "X....", "X....", "X....", "X....", "X....", "XXXXX"],
    "P": ["XXXX.", "X...X", "X...X", "XXXX.", "X....", "X....", "X...."],
    "A": [".XXX.", "X...X", "X...X", "XXXXX", "X...X", "X...X", "X...X"],
    "T": ["XXXXX", "..X..", "..X..", "..X..", "..X..", "..X..", "..X.."],
    " ": [".....", ".....", ".....", ".....", ".....", ".....", "....."],
}


def render_banner(pal: Palette, text: str = "NULLPAT", sub: str = "") -> str:
    glyphs = [_FONT_5X7.get(ch, _FONT_5X7[" "]) for ch in text.upper()]
    width = sum(len(g[0]) for g in glyphs) + (len(glyphs) - 1)
    lines = []
    for row in range(7):
        chunks = []
        col_cursor = 0
        for gi, glyph in enumerate(glyphs):
            for px in glyph[row]:
                t = col_cursor / max(1, width - 1)
                rgb = lerp(BLUE, RED, t)
                block = "\u2588\u2588" if px == "X" else "  "
                chunks.append(pal.rgb(block, rgb, bold=True))
                col_cursor += 1
            if gi != len(glyphs) - 1:
                chunks.append("  ")
                col_cursor += 1
        lines.append("".join(chunks))
    banner = "\n".join(lines)
    rule = pal.dim("\u2500" * 70)
    tagline = pal.dim(f"  v{VERSION} \u00b7 null-session password audit reporting \u00b7 fork of DPAT")
    out = banner + "\n" + tagline
    if sub:
        out += "\n" + pal.dim("  " + sub)
    out += "\n" + pal.rgb(f"  Built by {AUTHOR_NAME} ({AUTHOR_HANDLE})", BLUE, bold=True) + pal.dim(
        "  \u00b7  linkedin.com/in/budsec  \u00b7  github.com/buddysecurity  \u00b7  youtube.com/@BudSec")
    out += "\n" + rule
    return out


# --------------------------------------------------------------------------
# Progress / status line helpers
# --------------------------------------------------------------------------

class Status:
    def __init__(self, pal: Palette):
        self.pal = pal

    def step(self, msg):
        tag = self.pal.info("[*]")
        print(f"{tag} {msg}")

    def ok(self, msg):
        tag = self.pal.ok("[+]")
        print(f"{tag} {msg}")

    def warn(self, msg):
        tag = self.pal.warn("[!]")
        print(f"{tag} {msg}")

    def bad(self, msg):
        tag = self.pal.bad("[x]")
        print(f"{tag} {msg}")

    def progress(self, done, total, label):
        if not self.pal.enabled:
            return
        width = 28
        frac = 0 if total == 0 else min(1.0, done / total)
        filled = int(width * frac)
        bar = "\u2588" * filled + "\u2591" * (width - filled)
        rgb = lerp(BLUE, RED, frac)
        line = f"\r    {self.pal.rgb(bar, rgb)} {frac*100:5.1f}%  {label}"
        sys.stdout.write(line)
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

class Account:
    __slots__ = ("domain", "username", "rid", "lm_hash", "nt_hash",
                 "is_computer", "history_base", "history_index")

    def __init__(self, domain, username, rid, lm_hash, nt_hash,
                 is_computer=False, history_base=None, history_index=None):
        self.domain = domain
        self.username = username
        self.rid = rid
        self.lm_hash = lm_hash.lower()
        self.nt_hash = nt_hash.lower()
        self.is_computer = is_computer
        self.history_base = history_base
        self.history_index = history_index

    @property
    def full_name(self):
        return f"{self.domain}\\{self.username}" if self.domain else self.username


_HISTORY_RE = re.compile(r"^(?P<base>.+)_history(?P<idx>\d+)$", re.IGNORECASE)


def parse_ntds_line(line):
    """Parse one secretsdump.py-style NTDS line:
    DOMAIN\\user:RID:LMHASH:NTHASH:::  (optionally no domain)
    Returns an Account or None if the line can't be parsed.
    """
    line = line.rstrip("\n\r")
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 4:
        return None
    user_field, rid, lm_hash, nt_hash = parts[0], parts[1], parts[2], parts[3]
    if "\\" in user_field:
        domain, username = user_field.split("\\", 1)
    else:
        domain, username = "", user_field

    if not re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash or ""):
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{32}", lm_hash or ""):
        lm_hash = EMPTY_LM

    is_computer = username.endswith("$")

    history_base, history_index = None, None
    m = _HISTORY_RE.match(username)
    if m:
        history_base = m.group("base")
        history_index = int(m.group("idx"))

    return Account(domain, username, rid, lm_hash, nt_hash,
                    is_computer=is_computer,
                    history_base=history_base, history_index=history_index)


def parse_ntds(path, status: Status, include_computers=False, stats=None):
    stats = stats if stats is not None else {}
    stats.update({"lines": 0, "parsed": 0, "skipped": 0, "duplicates": 0,
                  "computers_excluded": 0, "history_entries": 0})
    accounts = []
    history = collections.defaultdict(list)
    seen_nt_rid = set()
    total_lines = sum(1 for _ in open(path, "r", errors="ignore"))
    with open(path, "r", errors="ignore") as fh:
        for i, line in enumerate(fh, start=1):
            if i % 2000 == 0 or i == total_lines:
                status.progress(i, total_lines, "parsing NTDS dump")
            stats["lines"] += 1
            acct = parse_ntds_line(line)
            if acct is None:
                stats["skipped"] += 1
                continue
            key = (acct.domain.lower(), acct.username.lower(), acct.rid)
            if key in seen_nt_rid:
                stats["duplicates"] += 1
                continue
            seen_nt_rid.add(key)
            stats["parsed"] += 1
            if acct.history_base is not None:
                stats["history_entries"] += 1
                history[(acct.domain.lower(), acct.history_base.lower())].append(acct)
                continue
            if acct.is_computer and not include_computers:
                stats["computers_excluded"] += 1
                continue
            accounts.append(acct)
    return accounts, history


def decode_hashcat_password(raw: str) -> str:
    """Decode hashcat's $HEX[...] escaping for passwords containing
    unprintable or delimiter-breaking characters."""
    m = re.fullmatch(r"\$HEX\[([0-9a-fA-F]*)\]", raw)
    if not m:
        return raw
    try:
        return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
    except ValueError:
        return raw


def parse_cracked_file(path, status: Status, stats=None):
    """Parses hash:password lines (hashcat potfile / john-style output).
    Returns a dict of lowercase hex hash -> recovered password."""
    stats = stats if stats is not None else {}
    stats.update({"lines": 0, "valid": 0, "invalid": 0, "duplicates": 0, "hex_decoded": 0})
    cracked = {}
    total_lines = sum(1 for _ in open(path, "r", errors="ignore"))
    with open(path, "r", errors="ignore") as fh:
        for i, line in enumerate(fh, start=1):
            if i % 2000 == 0 or i == total_lines:
                status.progress(i, total_lines, "parsing cracked-password list")
            stats["lines"] += 1
            line = line.rstrip("\n\r")
            if not line or ":" not in line:
                stats["invalid"] += 1
                continue
            hash_part, _, pwd_part = line.partition(":")
            hash_part = hash_part.strip().lower()
            if not re.fullmatch(r"[0-9a-f]{32}", hash_part):
                stats["invalid"] += 1
                continue
            if pwd_part.startswith("$HEX["):
                stats["hex_decoded"] += 1
            if hash_part in cracked:
                stats["duplicates"] += 1
            else:
                stats["valid"] += 1
            cracked[hash_part] = decode_hashcat_password(pwd_part)
    return cracked


def load_name_list(path):
    if not path:
        return set()
    with open(path, "r", errors="ignore") as fh:
        return {line.strip().lower() for line in fh if line.strip() and not line.startswith("#")}


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def password_traits(pwd: str):
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)
    score = sum([has_upper, has_lower, has_digit, has_special])
    return has_upper, has_lower, has_digit, has_special, score


def strength_bucket(length, score):
    if length < 8 or score <= 1:
        return "Very Weak"
    if length < 12 and score == 2:
        return "Weak"
    if (length < 12 and score >= 3) or (length >= 12 and score == 2):
        return "Moderate"
    return "Stronger"


STRENGTH_ORDER = ["Very Weak", "Weak", "Moderate", "Stronger"]
STRENGTH_COLOR = {
    "Very Weak": RED,
    "Weak": (0xe0, 0x7a, 0x1f),
    "Moderate": (0xc9, 0xa4, 0x1f),
    "Stronger": (0x1f, 0x8a, 0x4c),
}


def analyze(accounts, history, cracked_hashes, admins, disabled, weak_patterns,
            min_length, company_patterns, status: Status):
    results = {}
    total = len(accounts)
    results["total_accounts"] = total

    cracked_accounts = []
    not_cracked = []
    empty_password_accounts = []
    lm_present_accounts = []
    pwd_to_users = collections.defaultdict(list)
    username_eq_password = []
    length_dist = collections.Counter()
    strength_counter = collections.Counter()
    pwd_counter = collections.Counter()
    admin_cracked = []
    weak_hits = []

    for i, acct in enumerate(accounts, start=1):
        if i % 2500 == 0 or i == total:
            status.progress(i, total, "correlating accounts against cracked hashes")

        is_disabled = acct.username.lower() in disabled
        is_admin = acct.username.lower() in admins

        if acct.nt_hash == EMPTY_NT:
            empty_password_accounts.append(acct)
            continue

        if acct.lm_hash != EMPTY_LM:
            lm_present_accounts.append(acct)

        pwd = cracked_hashes.get(acct.nt_hash)
        if pwd is None:
            not_cracked.append(acct)
            continue

        has_upper, has_lower, has_digit, has_special, score = password_traits(pwd)
        bucket = strength_bucket(len(pwd), score)
        row = {
            "domain": acct.domain,
            "username": acct.username,
            "full_name": acct.full_name,
            "password": pwd,
            "length": len(pwd),
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "complexity_score": score,
            "bucket": bucket,
            "is_admin": is_admin,
            "is_disabled": is_disabled,
        }
        cracked_accounts.append(row)
        pwd_to_users[pwd].append(acct.full_name)
        length_dist[min(len(pwd), 16)] += 1
        strength_counter[bucket] += 1
        pwd_counter[pwd] += 1
        if is_admin:
            admin_cracked.append(row)
        if pwd.lower() == acct.username.lower():
            username_eq_password.append(row)

        all_patterns = list(weak_patterns) + list(company_patterns)
        for pattern, label in all_patterns:
            if re.search(pattern, pwd, re.IGNORECASE):
                weak_hits.append({**row, "pattern_label": label})
                break

    reuse_groups = [
        {"password": pwd, "count": len(users), "usernames": sorted(users)}
        for pwd, users in pwd_to_users.items() if len(users) > 1
    ]
    reuse_groups.sort(key=lambda g: (-g["count"], g["password"]))

    # history reuse: does a user's CURRENT cracked password match a PRIOR
    # (historical) hash also present in the cracked set, or vice versa --
    # i.e. are they cycling through the same small set of passwords?
    history_reuse = []
    current_by_key = {(a.domain.lower(), a.username.lower()): a for a in accounts}
    for (domain, base_user), hist_accounts in history.items():
        cur = current_by_key.get((domain, base_user))
        hist_pwds = []
        for h in hist_accounts:
            p = cracked_hashes.get(h.nt_hash)
            if p:
                hist_pwds.append((h.history_index, p))
        cur_pwd = cracked_hashes.get(cur.nt_hash) if cur else None
        recovered_total = len(hist_pwds) + (1 if cur_pwd else 0)
        if recovered_total >= 2:
            examples = sorted(hist_pwds) + ([(-1, cur_pwd)] if cur_pwd else [])
            history_reuse.append({
                "username": cur.full_name if cur else f"{domain}\\{base_user}",
                "recovered_count": recovered_total,
                "passwords": [p for _, p in examples],
            })

    cracked_count = len(cracked_accounts)
    results.update({
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cracked_accounts": cracked_accounts,
        "not_cracked_count": len(not_cracked),
        "cracked_count": cracked_count,
        "cracked_pct": (cracked_count / total * 100) if total else 0.0,
        "empty_password_accounts": [a.full_name for a in empty_password_accounts],
        "lm_present_accounts": [a.full_name for a in lm_present_accounts],
        "reuse_groups": reuse_groups,
        "reused_account_count": sum(g["count"] for g in reuse_groups),
        "username_eq_password": username_eq_password,
        "length_distribution": dict(sorted(length_dist.items())),
        "strength_breakdown": {k: strength_counter.get(k, 0) for k in STRENGTH_ORDER},
        "top_passwords": pwd_counter.most_common(),
        "admin_total": len(admins),
        "admin_cracked": sorted(admin_cracked, key=lambda r: r["username"].lower()),
        "weak_pattern_hits": weak_hits,
        "short_password_count": sum(1 for r in cracked_accounts if r["length"] < min_length),
        "min_length_flag": min_length,
        "history_reuse": history_reuse,
    })
    extend_stats(results, accounts, history, cracked_hashes, admins, disabled, min_length)
    return results


def _median(vals):
    vals = sorted(vals)
    n = len(vals)
    if not n:
        return 0
    mid = n // 2
    return vals[mid] if n % 2 else (vals[mid - 1] + vals[mid]) / 2


def extend_stats(results, accounts, history, cracked_hashes, admins, disabled, min_length):
    """Adds the fully-labelled statistics the dashboard needs: composition,
    domain breakdown, privileged/disabled exposure, reuse blast radius."""
    rows = results["cracked_accounts"]
    n = len(rows)
    lens = [r["length"] for r in rows]
    pwds = [r["password"] for r in rows]
    year_re = re.compile(r"(19|20)\d{2}")

    def cnt(fn):
        return sum(1 for r in rows if fn(r))

    results["unique_nt_hashes"] = len({a.nt_hash for a in accounts})
    results["unique_passwords"] = len(set(pwds))
    results["length_stats"] = {
        "min": min(lens) if lens else 0, "max": max(lens) if lens else 0,
        "avg": (sum(lens) / n) if n else 0.0, "median": _median(lens),
    }
    results["composition"] = [
        ("Contains uppercase", cnt(lambda r: r["has_upper"])),
        ("Contains lowercase", cnt(lambda r: r["has_lower"])),
        ("Contains digit", cnt(lambda r: r["has_digit"])),
        ("Contains special character", cnt(lambda r: r["has_special"])),
        ("Lowercase letters only", cnt(lambda r: r["has_lower"] and not (r["has_upper"] or r["has_digit"] or r["has_special"]))),
        ("Digits only", cnt(lambda r: r["has_digit"] and not (r["has_upper"] or r["has_lower"] or r["has_special"]))),
        ("Letters only (no digit / special)", cnt(lambda r: (r["has_upper"] or r["has_lower"]) and not (r["has_digit"] or r["has_special"]))),
        ("All four character classes", cnt(lambda r: r["complexity_score"] == 4)),
        ("Ends with a digit", sum(1 for p in pwds if p and p[-1].isdigit())),
        ("Starts uppercase + ends digit/symbol", sum(1 for p in pwds if p and p[0].isupper() and not p[-1].isalpha())),
        ("Contains a year (19xx / 20xx)", sum(1 for p in pwds if year_re.search(p))),
        (f"Meets policy (>= {min_length} chars, 3+ classes)", cnt(lambda r: r["length"] >= min_length and r["complexity_score"] >= 3)),
    ]
    sc = collections.Counter(r["complexity_score"] for r in rows)
    results["complexity_distribution"] = [(k, sc.get(k, 0)) for k in (1, 2, 3, 4)]

    # per-domain breakdown
    dom = collections.OrderedDict()
    for a in accounts:
        d = dom.setdefault(a.domain or "(no domain)", {"total": 0, "cracked": 0, "blank": 0})
        d["total"] += 1
        if a.nt_hash == EMPTY_NT:
            d["blank"] += 1
        elif a.nt_hash in cracked_hashes:
            d["cracked"] += 1
    results["domain_breakdown"] = [
        {"domain": k, **v, "not_cracked": v["total"] - v["cracked"] - v["blank"]} for k, v in dom.items()
    ]

    # privileged / disabled exposure
    present = {a.username.lower(): a for a in accounts}
    results["admin_found"] = sorted(u for u in admins if u in present)
    results["admin_not_found"] = sorted(u for u in admins if u not in present)
    results["admin_blank"] = sorted(present[u].full_name for u in admins
                                    if u in present and present[u].nt_hash == EMPTY_NT)
    results["disabled_total"] = len(disabled)
    results["disabled_cracked"] = sum(1 for r in rows if r["is_disabled"])
    results["enabled_cracked"] = n - results["disabled_cracked"]

    # reuse blast radius
    groups = results["reuse_groups"]
    results["reuse_group_count"] = len(groups)
    results["largest_reuse"] = groups[0] if groups else None
    results["history_account_count"] = len(history)
    results["below_complexity_count"] = cnt(lambda r: r["complexity_score"] < 3)
    return results


def risk_rating(results):
    pct = results["cracked_pct"]
    if pct >= 30 or results["admin_cracked"]:
        return "CRITICAL"
    if pct >= 15 or results["reused_account_count"] >= 10:
        return "HIGH"
    if pct >= 5:
        return "MEDIUM"
    return "LOW"


RISK_COLOR = {
    "CRITICAL": RED,
    "HIGH": (0xe0, 0x7a, 0x1f),
    "MEDIUM": (0xc9, 0xa4, 0x1f),
    "LOW": (0x1f, 0x8a, 0x4c),
}


# --------------------------------------------------------------------------
# Terminal summary
# --------------------------------------------------------------------------

def print_summary(results, pal: Palette):
    rating = risk_rating(results)
    print()
    print(pal.bold("  AUDIT SUMMARY"))
    print(pal.dim("  " + "\u2500" * 44))

    def row(label, value, color=None):
        v = pal.rgb(str(value), color, bold=True) if color else pal.bold(str(value))
        print(f"  {label:<32}{v}")

    row("Accounts analyzed", results["total_accounts"])
    row("Passwords cracked", f'{results["cracked_count"]} ({results["cracked_pct"]:.1f}%)',
        RED if results["cracked_pct"] >= 15 else (0xc9, 0xa4, 0x1f))
    row("Blank passwords", len(results["empty_password_accounts"]),
        RED if results["empty_password_accounts"] else (0x1f, 0x8a, 0x4c))
    row("LM hashes stored", len(results["lm_present_accounts"]),
        RED if results["lm_present_accounts"] else (0x1f, 0x8a, 0x4c))
    row("Accounts w/ reused password", results["reused_account_count"],
        (0xe0, 0x7a, 0x1f) if results["reused_account_count"] else (0x1f, 0x8a, 0x4c))
    row("Privileged accounts cracked", f'{len(results["admin_cracked"])} / {results["admin_total"]}',
        RED if results["admin_cracked"] else (0x1f, 0x8a, 0x4c))
    row("Username == password", len(results["username_eq_password"]),
        RED if results["username_eq_password"] else (0x1f, 0x8a, 0x4c))
    row("Weak-pattern matches", len(results["weak_pattern_hits"]))
    print(pal.dim("  " + "\u2500" * 44))
    print(f'  {"Overall risk rating":<32}' + pal.rgb(f" {rating} ", RISK_COLOR[rating], bold=True))
    print()


# --------------------------------------------------------------------------
# Findings / risk register (every finding gets a stable ID for traceability)
# --------------------------------------------------------------------------

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Pass"]
SEV_CLASS = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low", "Pass": "pass"}


def pct(n, d):
    return (n / d * 100) if d else 0.0


def fmt_pct(n, d):
    return f"{pct(n, d):.1f}%"


def risk_reasons(results):
    """Human-readable explanation of why the overall rating is what it is."""
    reasons = []
    p = results["cracked_pct"]
    if results["admin_cracked"]:
        reasons.append(f'{len(results["admin_cracked"])} privileged account(s) cracked (forces CRITICAL)')
    if p >= 30:
        reasons.append(f"crack rate {p:.1f}% is >= 30% (CRITICAL threshold)")
    elif p >= 15:
        reasons.append(f"crack rate {p:.1f}% is >= 15% (HIGH threshold)")
    elif p >= 5:
        reasons.append(f"crack rate {p:.1f}% is >= 5% (MEDIUM threshold)")
    else:
        reasons.append(f"crack rate {p:.1f}% is below 5% (LOW)")
    if results["reused_account_count"] >= 10:
        reasons.append(f'{results["reused_account_count"]} accounts share reused passwords (>= 10 = HIGH)')
    return reasons


def build_findings(r, meta):
    total = r["total_accounts"]
    cracked = r["cracked_count"]
    findings = []

    def add(sev, title, count, base, impact, rec, anchor):
        status_sev = sev if count else "Pass"
        findings.append({
            "id": f"NP-{len(findings) + 1:02d}", "severity": status_sev, "title": title,
            "count": count, "pct": fmt_pct(count, base), "base": base,
            "impact": impact, "recommendation": rec, "anchor": anchor,
        })

    p = r["cracked_pct"]
    sev = "Critical" if p >= 30 else "High" if p >= 15 else "Medium" if p >= 5 else "Low"
    add(sev, "Passwords recovered from the hash dump", cracked, total,
        "Every cracked account can be authenticated to by anyone holding the hash dump; "
        "the credentials are effectively public to an attacker.",
        "Force a password reset for every cracked account, enforce a longer minimum length "
        "(14+), and deploy a banned-password list.", "accounts")
    add("Critical", "Privileged accounts with recovered / blank passwords",
        len(r["admin_cracked"]) + len(r["admin_blank"]), max(meta["admin_total"], 1),
        "Compromise of a privileged credential typically means full domain takeover.",
        "Rotate immediately, move to long random passwords / passphrases, enforce MFA and tiered "
        "admin accounts, and use gMSA / LAPS where applicable.", "privileged")
    add("Critical", "Accounts with blank (empty) passwords", len(r["empty_password_accounts"]), total,
        "Accounts can be accessed with no secret at all.",
        "Set a strong password or disable the accounts; enable 'password not required' auditing.",
        "blanklm")
    add("High", "Accounts sharing a reused password", r["reused_account_count"], total,
        "One compromised password unlocks every account in its group (lateral movement / blast radius).",
        "Force unique passwords per account; investigate shared / service credentials.", "reuse")
    add("High", "Username equals password", len(r["username_eq_password"]), total,
        "Trivially guessable - the first thing any password-spray tries.",
        "Reset and block passwords that contain or equal the account name.", "ueq")
    add("High", "Legacy LM hashes still stored", len(r["lm_present_accounts"]), total,
        "LM hashes are split-and-uppercased and are cracked almost instantly.",
        "Enable 'Do not store LAN Manager hash value on next password change' and rotate affected passwords.",
        "blanklm")
    weak_base = max(cracked, 1)
    wsev = "High" if pct(len(r["weak_pattern_hits"]), weak_base) >= 25 else "Medium"
    add(wsev, "Passwords matching common weak patterns", len(r["weak_pattern_hits"]), cracked,
        "Season/year, 'password', keyboard-walk and company-name patterns are the first guesses in any spray or wordlist.",
        "Add the matched patterns to a banned-password list (Azure AD Password Protection / custom filter).",
        "weak")
    add("Medium", f'Passwords shorter than the {r["min_length_flag"]}-character policy',
        r["short_password_count"], cracked,
        "Short passwords fall quickly to brute force even when they look complex.",
        f'Raise the minimum length to at least 14 characters and favour passphrases.', "length")
    add("Medium", "Passwords with weak complexity (fewer than 3 character classes)",
        r["below_complexity_count"], cracked,
        "Low character variety greatly reduces the search space.",
        "Enforce length-first policy plus a banned-password list rather than composition rules alone.",
        "strength")
    add("Medium", "Accounts cycling through the same passwords (history)",
        len(r["history_reuse"]), max(r["history_account_count"], 1),
        "Users rotate between a small set of passwords, so forced expiry gives little real protection.",
        "Increase password history depth, block similar-to-previous passwords, and move away from forced expiry.",
        "history")
    add("Low", "Disabled accounts with recovered passwords", r["disabled_cracked"], max(cracked, 1),
        "Disabled accounts can often be re-enabled by an attacker with sufficient rights.",
        "Delete stale disabled accounts, or reset their passwords to long random values.", "accounts")
    return findings


# --------------------------------------------------------------------------
# SVG mini-charts (no JS charting library, fully self-contained)
# --------------------------------------------------------------------------

def _hexc(rgb):
    return "#%02x%02x%02x" % rgb


def svg_donut(parts, size=190):
    """parts: list of (label, value, rgb). Centre shows the first part's share."""
    total = sum(v for _, v, _ in parts) or 1
    r, cx, cy = size / 2 - 12, size / 2, size / 2
    circumference = 2 * 3.14159265 * r
    offset = 0
    segs = ['<circle cx="%s" cy="%s" r="%s" fill="none" stroke="#eef0f8" stroke-width="22"/>' % (cx, cy, r)]
    for label, value, rgb in parts:
        dash = circumference * (value / total)
        if value:
            segs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{_hexc(rgb)}" '
                f'stroke-width="22" stroke-dasharray="{dash:.2f} {circumference:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
                f'<title>{html.escape(label)}: {value}</title></circle>')
        offset += dash
    pct_first = (parts[0][1] / total * 100) if total else 0
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="account status donut">'
        + "".join(segs) +
        f'<text x="{cx}" y="{cy}" text-anchor="middle" class="donut-num">{pct_first:.0f}%</text>'
        f'<text x="{cx}" y="{cy+18}" text-anchor="middle" class="donut-sub">cracked</text></svg>')


def svg_bars(labels, values, rgb, width=640, height=190):
    """Vertical bars with the value printed above every bar."""
    if not values or not any(values):
        return '<p class="muted">No data.</p>'
    maxv = max(values) or 1
    n = len(values)
    pad_l, pad_b, pad_t, gap = 10, 26, 18, 6
    bw = max(8, (width - pad_l * 2 - gap * (n - 1)) / n)
    out = []
    for i, (lab, val) in enumerate(zip(labels, values)):
        bh = (height - pad_b - pad_t) * (val / maxv)
        x = pad_l + i * (bw + gap)
        y = height - pad_b - bh
        out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="2" fill="{_hexc(rgb)}">'
                   f'<title>{html.escape(str(lab))}: {val}</title></rect>')
        out.append(f'<text x="{x+bw/2:.1f}" y="{y-4:.1f}" text-anchor="middle" class="bar-val">{val}</text>')
        out.append(f'<text x="{x+bw/2:.1f}" y="{height-pad_b+14}" text-anchor="middle" class="bar-label">'
                   f'{html.escape(str(lab))}</text>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'preserveAspectRatio="xMinYMin meet" role="img">' + "".join(out) + '</svg>')


def hbars(items, total, color="#204399", mask=False):
    """items: list of (label, value[, colour]). Fully labelled horizontal bars: count and percentage."""
    if not items:
        return '<p class="muted">No data.</p>'
    maxv = max(i[1] for i in items) or 1
    out = []
    for it in items:
        label, value = it[0], it[1]
        c = it[2] if len(it) > 2 else color
        w = (value / maxv * 100) if maxv else 0
        span_cls = ' class="pwd"' if mask else ""
        out.append(
            f'<div class="hb"><div class="hb-l"><span{span_cls}>{esc(label)}</span></div>'
            f'<div class="track"><div class="fill" style="width:{w:.1f}%;background:{c}"></div></div>'
            f'<div class="hb-v"><b>{value}</b> <span class="muted">{fmt_pct(value, total)}</span></div></div>')
    return "".join(out)


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

HTML_CSS = """
:root{
  --blue:#204399; --blue-ink:#182f6e; --navy:#0e1738; --red:#ec1b3c; --ink:#161c2e;
  --muted:#6b748c; --line:#e4e7ef; --bg:#f3f5fa; --card:#ffffff;
  --crit:#ec1b3c; --high:#e07a1f; --med:#c9a41f; --low:#1f8a4c; --pass:#1f8a4c; --info:#204399;
  font-family:"IBM Plex Sans","Segoe UI",system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{margin:0;background:var(--bg);color:var(--ink);font-size:14.5px;line-height:1.5;}
code,.mono,td.pwd,.pwd,.hash{font-family:"IBM Plex Mono","SFMono-Regular",Consolas,monospace;}
a{color:var(--blue);text-decoration:none;} a:hover{text-decoration:underline;}
.muted{color:var(--muted);}

/* masthead */
header.masthead{background:linear-gradient(120deg,var(--blue) 0%,var(--blue-ink) 55%,var(--navy) 100%);color:#fff;padding:30px 40px 24px;}
.mast-top{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;align-items:flex-start;}
.brand{display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
.brand .mark{font-size:30px;font-weight:700;letter-spacing:.5px;} .brand .pat{color:var(--red);}
.tag{color:#c7d0ef;font-size:13px;margin-top:4px;}
.meta{margin-top:16px;display:flex;gap:26px;flex-wrap:wrap;font-size:13px;color:#dfe4f8;}
.meta b{color:#fff;}
.author{text-align:right;font-size:12.5px;color:#c7d0ef;}
.author .by{font-size:14px;color:#fff;font-weight:600;}
.links{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;justify-content:flex-end;}
.links a{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(255,255,255,.35);color:#fff;
  padding:4px 11px;border-radius:20px;font-size:12px;} .links a:hover{background:rgba(255,255,255,.14);text-decoration:none;}
.links a i{width:8px;height:8px;border-radius:50%;display:inline-block;}
.risk-badge{display:inline-block;padding:3px 12px;border-radius:3px;font-weight:700;font-size:12px;letter-spacing:.5px;color:#fff;}

/* layout */
.layout{display:grid;grid-template-columns:250px minmax(0,1fr);max-width:1560px;margin:0 auto;}
aside.sidebar{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;padding:18px 14px;
  background:#fff;border-right:1px solid var(--line);display:flex;flex-direction:column;gap:14px;}
aside .navtitle{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:2px 6px;}
nav.toc a{display:flex;align-items:center;gap:9px;padding:7px 9px;border-radius:5px;color:var(--ink);font-size:13.5px;}
nav.toc a:hover{background:#eef1fb;text-decoration:none;}
nav.toc a.active{background:var(--blue);color:#fff;}
nav.toc a .n{font-size:11px;opacity:.6;width:18px;} nav.toc a.active .n{opacity:.85;}
nav.toc a .pill{margin-left:auto;font-size:11px;background:#eef0f8;color:var(--muted);border-radius:10px;padding:0 7px;}
nav.toc a.active .pill{background:rgba(255,255,255,.22);color:#fff;}
.authorcard{margin-top:auto;border:1px solid var(--line);border-radius:8px;padding:12px;font-size:12.5px;background:#f8f9fd;}
.authorcard b{display:block;font-size:13.5px;}
.authorcard a{display:block;margin-top:3px;}
main{padding:0 32px 60px;min-width:0;}

/* toolbar */
.toolbar{position:sticky;top:0;z-index:20;background:var(--bg);padding:12px 0;display:flex;gap:8px;flex-wrap:wrap;
  align-items:center;border-bottom:1px solid var(--line);margin-bottom:20px;}
.toolbar button,.btn{border:1px solid var(--line);background:#fff;color:var(--ink);padding:7px 13px;border-radius:5px;
  font-size:13px;cursor:pointer;font-family:inherit;}
.toolbar button:hover,.btn:hover{border-color:var(--blue);color:var(--blue);}
.toolbar .spacer{flex:1;}
.toolbar .hint{font-size:12px;color:var(--muted);}

/* collapsible sections */
details.sec{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:16px;scroll-margin-top:70px;}
details.sec>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 18px;user-select:none;}
details.sec>summary::-webkit-details-marker{display:none;}
details.sec>summary:hover{background:#fafbff;border-radius:8px;}
details.sec>summary .num{font-size:12px;font-weight:700;color:#fff;background:var(--blue);border-radius:4px;padding:1px 7px;}
details.sec>summary h2{font-size:17px;margin:0;font-weight:650;}
details.sec>summary .count{font-size:12px;background:#eef0f8;color:var(--muted);border-radius:10px;padding:1px 10px;}
details.sec>summary .count.bad{background:#fde3e7;color:var(--crit);font-weight:600;}
details.sec>summary .chev{margin-left:auto;transition:transform .15s;color:var(--muted);font-size:18px;}
details.sec[open]>summary .chev{transform:rotate(90deg);}
details.sec[open]>summary{border-bottom:1px solid var(--line);}
.sec-body{padding:18px 20px 14px;}
.sec-body p.desc{color:var(--muted);font-size:13.5px;margin:0 0 16px;}
.sec-nav{display:flex;gap:14px;justify-content:space-between;margin-top:18px;padding-top:10px;border-top:1px dashed var(--line);font-size:12.5px;}
h3.sub{font-size:14px;margin:20px 0 8px;}

/* dashboard */
.hero{display:grid;grid-template-columns:1.15fr 1fr 1fr;gap:14px;margin-bottom:18px;}
.panel{border:1px solid var(--line);border-radius:8px;padding:16px 18px;background:#fff;}
.panel h4{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);}
.riskcard{background:linear-gradient(135deg,var(--navy),var(--blue-ink));color:#fff;border:none;}
.riskcard h4{color:#aab4dc;}
.riskcard .big{font-size:38px;font-weight:800;letter-spacing:.5px;line-height:1.1;}
.riskcard ul{margin:10px 0 0;padding-left:18px;font-size:12.5px;color:#d5dbf3;}
.meter{display:flex;gap:4px;margin-top:14px;}
.meter span{flex:1;height:8px;border-radius:4px;background:rgba(255,255,255,.18);}
.meter span.on{opacity:1;} .meter .m-low.on{background:var(--low);} .meter .m-med.on{background:var(--med);}
.meter .m-high.on{background:var(--high);} .meter .m-crit.on{background:var(--crit);}
.meterlbl{display:flex;justify-content:space-between;font-size:10.5px;color:#aab4dc;margin-top:3px;}
.donutwrap{display:flex;gap:16px;align-items:center;flex-wrap:wrap;}
.legend div{margin:5px 0;font-size:13px;} .legend .sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:7px;}
.donut-num{font-size:26px;font-weight:700;fill:var(--ink);} .donut-sub{font-size:11px;fill:var(--muted);}
.bar-label{font-size:10px;fill:var(--muted);} .bar-val{font-size:10px;fill:var(--ink);font-weight:600;}
.sevrow{display:flex;gap:8px;flex-wrap:wrap;}
.sevbox{flex:1;min-width:70px;border-radius:6px;padding:8px 10px;text-align:center;color:#fff;}
.sevbox b{display:block;font-size:22px;line-height:1.1;} .sevbox span{font-size:11px;opacity:.95;}
.sev-crit{background:var(--crit);} .sev-high{background:var(--high);} .sev-med{background:var(--med);}
.sev-low{background:var(--low);} .sev-pass{background:#5f6b86;}
.kgroup{margin:20px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);font-weight:700;}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));gap:10px;}
a.card{display:block;background:#fff;border:1px solid var(--line);border-left:3px solid var(--blue);border-radius:6px;
  padding:11px 13px;color:var(--ink);transition:box-shadow .12s,transform .12s;}
a.card:hover{box-shadow:0 3px 12px rgba(20,30,70,.12);transform:translateY(-1px);text-decoration:none;}
a.card.alert{border-left-color:var(--crit);} a.card.good{border-left-color:var(--low);}
.card .num{font-size:24px;font-weight:700;line-height:1.2;} .card .lbl{font-size:12.5px;color:var(--muted);}
.card .sub{font-size:11.5px;color:var(--muted);margin-top:2px;}
.card .go{font-size:11px;color:var(--blue);margin-top:4px;display:block;}

/* tables & bars */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;}
table{width:100%;border-collapse:collapse;background:#fff;font-size:13.5px;}
th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;}
th{background:#eef0f8;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.3px;color:var(--muted);white-space:nowrap;}
th.sortable{cursor:pointer;} th.sortable:hover{color:var(--blue);} th.sortable::after{content:" \\2195";opacity:.4;}
tr:last-child td{border-bottom:none;} tbody tr:hover{background:#fafbff;}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;} td.nw{white-space:nowrap;}
.pwd{filter:blur(5px);transition:filter .1s;user-select:none;}
body.reveal .pwd{filter:none;user-select:text;}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap;}
.badge.vweak{background:#fde3e7;color:var(--crit);} .badge.weak{background:#fcebd9;color:var(--high);}
.badge.moderate{background:#faf3d6;color:#8a6d00;} .badge.stronger{background:#dff2e6;color:var(--low);}
.badge.priv{background:var(--crit);color:#fff;} .badge.flag{background:#eef0f8;color:var(--muted);}
.badge.sev-crit,.badge.sev-high,.badge.sev-med,.badge.sev-low,.badge.sev-pass{color:#fff;}
.badge.sev-pass{background:var(--pass);}
input.filter{padding:7px 10px;border:1px solid var(--line);border-radius:5px;font-size:13px;width:280px;max-width:100%;}
.filterbar{display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap;}
.rowcount{font-size:12px;color:var(--muted);}
.empty-state{color:var(--muted);font-size:13.5px;padding:14px;background:#fafbff;border:1px dashed var(--line);border-radius:6px;}
.hb{display:grid;grid-template-columns:minmax(70px,190px) minmax(40px,1fr) auto;gap:10px;align-items:center;margin:6px 0;font-size:13px;}
.hb .track{background:#eef0f8;border-radius:4px;height:14px;overflow:hidden;} .hb .fill{height:100%;border-radius:4px;}
.hb-v{text-align:right;white-space:nowrap;}
.two{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px;} .three{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;}
.panel{min-width:0;} .hb-l{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
details.group{border:1px solid var(--line);border-radius:6px;margin-bottom:8px;background:#fff;}
details.group summary{padding:9px 14px;cursor:pointer;font-size:13.5px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
details.group summary b{color:var(--blue);} details.group .members{padding:2px 16px 12px;color:var(--muted);font-size:13px;}
ul.scroll{max-height:260px;overflow:auto;margin:0;padding:8px 8px 8px 26px;border:1px solid var(--line);border-radius:6px;background:#fff;font-size:13px;}
.kv td:first-child{color:var(--muted);width:240px;white-space:nowrap;} .kv td{border-bottom:1px solid var(--line);}
.trace{font-size:11.5px;color:var(--muted);}
.sevlegend span{margin-right:12px;font-size:12.5px;}
footer.disclaimer{margin-top:30px;padding:14px 18px;background:#fff6f7;border:1px solid #f3c3cb;border-radius:6px;color:#7a1626;font-size:13px;}
footer.disclaimer b{display:block;margin-bottom:3px;}
footer.credit{margin-top:18px;padding:16px 18px;background:#fff;border:1px solid var(--line);border-radius:8px;font-size:13px;
  display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center;}
footer.credit .links{justify-content:flex-start;margin:0;} footer.credit .links a{color:var(--blue);border-color:var(--line);}
footer.credit .links a:hover{background:#eef1fb;}
#totop{position:fixed;right:20px;bottom:20px;z-index:30;display:none;}
@media (max-width:1100px){.hero{grid-template-columns:minmax(0,1fr);} .two,.three{grid-template-columns:minmax(0,1fr);}}
@media (max-width:900px){
  .layout{grid-template-columns:1fr;} aside.sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line);}
  nav.toc{display:flex;flex-wrap:wrap;gap:4px;} .authorcard{margin-top:0;} main{padding:0 14px 50px;}
  header.masthead{padding:22px 18px;} .author,.links{text-align:left;justify-content:flex-start;}
}
@media print{
  aside.sidebar,.toolbar,#totop,.sec-nav,.filterbar{display:none!important;} .layout{display:block;}
  .pwd{filter:blur(5px);} body.reveal .pwd{filter:none;} details.sec{break-inside:avoid-page;}
}
"""

HTML_JS = """
(function(){
  var secs = function(){ return Array.prototype.slice.call(document.querySelectorAll('details.sec')); };
  function openFor(el){ // open every collapsed <details> that contains el
    var d = el;
    while(d){ if(d.tagName==='DETAILS'){ d.open = true; } d = d.parentElement; }
  }
  function go(id, push){
    var el = document.getElementById(id); if(!el) return;
    openFor(el);
    el.scrollIntoView({behavior:'smooth', block:'start'});
    if(push!==false && history.pushState){ history.pushState(null,'','#'+id); }
    setActive(id);
  }
  function setActive(id){
    document.querySelectorAll('nav.toc a').forEach(function(a){
      a.classList.toggle('active', a.getAttribute('data-sec')===id);
    });
  }
  document.addEventListener('click', function(e){
    var a = e.target.closest ? e.target.closest('a[href^="#"]') : null;
    if(!a) return;
    var id = a.getAttribute('href').slice(1);
    if(!id){ e.preventDefault(); window.scrollTo({top:0,behavior:'smooth'}); return; }
    if(document.getElementById(id)){ e.preventDefault(); go(id); }
  });
  window.addEventListener('hashchange', function(){ var id=location.hash.slice(1); if(id) go(id,false); });
  window.expandAll = function(open){
    secs().forEach(function(d){ d.open = open; });
    document.querySelectorAll('details.group').forEach(function(d){ d.open = open; });
  };
  window.toggleReveal = function(btn){
    document.body.classList.toggle('reveal');
    btn.textContent = document.body.classList.contains('reveal') ? 'Mask passwords' : 'Reveal passwords';
  };
  window.filterTable = function(inputId, tableId, countId){
    var q = document.getElementById(inputId).value.toLowerCase();
    var rows = document.querySelectorAll('#'+tableId+' tbody tr'), shown = 0;
    rows.forEach(function(r){
      var hit = r.textContent.toLowerCase().indexOf(q) !== -1;
      r.style.display = hit ? '' : 'none'; if(hit) shown++;
    });
    var c = document.getElementById(countId); if(c) c.textContent = 'Showing ' + shown + ' of ' + rows.length;
  };
  window.filterGroups = function(inputId, wrapId){
    var q = document.getElementById(inputId).value.toLowerCase();
    document.querySelectorAll('#'+wrapId+' details.group').forEach(function(g){
      g.style.display = g.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
    });
  };
  document.querySelectorAll('th.sortable').forEach(function(th){
    th.addEventListener('click', function(){
      var table = th.closest('table'), idx = Array.prototype.indexOf.call(th.parentNode.children, th);
      var asc = th.getAttribute('data-dir') !== 'asc'; th.setAttribute('data-dir', asc ? 'asc' : 'desc');
      var body = table.tBodies[0], rows = Array.prototype.slice.call(body.rows);
      rows.sort(function(a,b){
        var x = a.cells[idx].getAttribute('data-v'), y = b.cells[idx].getAttribute('data-v');
        if(x===null) x = a.cells[idx].textContent; if(y===null) y = b.cells[idx].textContent;
        var nx = parseFloat(x), ny = parseFloat(y);
        var r = (!isNaN(nx) && !isNaN(ny)) ? nx-ny : String(x).localeCompare(String(y));
        return asc ? r : -r;
      });
      rows.forEach(function(r){ body.appendChild(r); });
    });
  });
  // scrollspy
  var links = {}; document.querySelectorAll('nav.toc a').forEach(function(a){ links[a.getAttribute('data-sec')] = a; });
  var spy = function(){
    var cur = null, y = 170;
    secs().forEach(function(d){ var r = d.getBoundingClientRect(); if(r.top <= y) cur = d.id; });
    if(cur) setActive(cur);
    var t = document.getElementById('totop'); if(t) t.style.display = window.scrollY > 500 ? 'block' : 'none';
  };
  window.addEventListener('scroll', spy, {passive:true}); spy();
  window.addEventListener('beforeprint', function(){ window.expandAll(true); });
  if(location.hash){ var id = location.hash.slice(1); setTimeout(function(){ go(id,false); }, 50); }
})();
"""


def esc(v):
    return html.escape(str(v), quote=True)


def bucket_class(bucket):
    return {"Very Weak": "vweak", "Weak": "weak", "Moderate": "moderate", "Stronger": "stronger"}[bucket]


def author_links_html(css_class="links"):
    return (
        f'<div class="{css_class}">'
        f'<a href="{AUTHOR_LINKEDIN}" target="_blank" rel="noopener noreferrer"><i style="background:#0a66c2"></i>LinkedIn</a>'
        f'<a href="{AUTHOR_GITHUB}" target="_blank" rel="noopener noreferrer"><i style="background:#8b949e"></i>GitHub</a>'
        f'<a href="{AUTHOR_YOUTUBE}" target="_blank" rel="noopener noreferrer"><i style="background:#ff0000"></i>YouTube</a>'
        '</div>')


def table_html(headers, rows_html, table_id="", sortable=True, empty_cols=None):
    """headers: list of (label, css_class)."""
    th = "".join(
        f'<th class="{c}{" sortable" if sortable else ""}">{esc(l)}</th>' for l, c in headers)
    tid = f' id="{table_id}"' if table_id else ""
    body = rows_html or f'<tr><td colspan="{len(headers)}" class="muted">No data.</td></tr>'
    return f'<div class="tablewrap"><table{tid}><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(results, meta, title):
    r = results
    rating = risk_rating(r)
    total = r["total_accounts"]
    cracked = r["cracked_count"]
    blank = len(r["empty_password_accounts"])
    notc = r["not_cracked_count"]
    findings = build_findings(r, meta)
    failing = [f for f in findings if f["severity"] != "Pass"]
    sev_counts = collections.Counter(f["severity"] for f in findings)
    rating_color = _hexc(RISK_COLOR[rating])
    ORANGE, AMBER, GREEN, GREY = (0xe0, 0x7a, 0x1f), (0xc9, 0xa4, 0x1f), (0x1f, 0x8a, 0x4c), (0xd8, 0xdc, 0xe8)

    # per-password lookups for table flags
    pw_count = dict(r["top_passwords"])
    weak_map = {h["full_name"]: h["pattern_label"] for h in r["weak_pattern_hits"]}
    ueq_set = {h["full_name"] for h in r["username_eq_password"]}

    # ---- section registry (id, title, count text, alert?) ----
    S = collections.OrderedDict()
    S["overview"] = ("Dashboard", f"{total} accounts", False)
    S["findings"] = ("Findings & Risk Register", f"{len(failing)} open / {len(findings)} checks", bool(failing))
    S["impact"] = ("Impact Assessment", f'{cracked + blank} compromised', bool(cracked + blank))
    S["accounts"] = ("Account Status & Cracked Accounts", f"{cracked} cracked", cracked > 0)
    S["strength"] = ("Strength & Composition", f"{sum(v for _, v in r['strength_breakdown'].items())} analysed", False)
    S["length"] = ("Length Distribution", f'avg {r["length_stats"]["avg"]:.1f}', False)
    S["top"] = ("Top Recovered Passwords", f'{len(r["top_passwords"])} unique', False)
    S["privileged"] = ("Privileged Accounts", f'{len(r["admin_cracked"])}/{meta["admin_total"]} cracked', bool(r["admin_cracked"]))
    S["reuse"] = ("Password Reuse", f'{r["reuse_group_count"]} groups', r["reuse_group_count"] > 0)
    S["ueq"] = ("Username = Password", str(len(r["username_eq_password"])), bool(r["username_eq_password"]))
    S["weak"] = ("Weak-Pattern Matches", str(len(r["weak_pattern_hits"])), bool(r["weak_pattern_hits"]))
    S["history"] = ("Password History Reuse", str(len(r["history_reuse"])), bool(r["history_reuse"]))
    S["blanklm"] = ("Blank Passwords & LM Hashes", f'{blank} blank / {len(r["lm_present_accounts"])} LM', bool(blank or r["lm_present_accounts"]))
    S["audit"] = ("Audit Trail & Methodology", "traceability", False)
    keys = list(S.keys())

    def sec(sid, body, desc=""):
        i = keys.index(sid)
        t, count, bad = S[sid]
        prev_l = f'<a href="#{keys[i-1]}">&larr; {esc(S[keys[i-1]][0])}</a>' if i > 0 else "<span></span>"
        next_l = f'<a href="#{keys[i+1]}">{esc(S[keys[i+1]][0])} &rarr;</a>' if i < len(keys) - 1 else "<span></span>"
        d = f'<p class="desc">{desc}</p>' if desc else ""
        return (
            f'<details class="sec" id="{sid}" open><summary><span class="num">{i+1:02d}</span><h2>{esc(t)}</h2>'
            f'<span class="count{" bad" if bad else ""}">{esc(count)}</span><span class="chev">&rsaquo;</span></summary>'
            f'<div class="sec-body">{d}{body}'
            f'<div class="sec-nav">{prev_l}<a href="#overview">&uarr; Back to dashboard</a>{next_l}</div></div></details>')

    def card(label, value, sub="", target="", alert=False, good=False):
        cls = "card" + (" alert" if alert else "") + (" good" if good else "")
        go = f'<span class="go">View details &rarr;</span>' if target else ""
        href = f' href="#{target}"' if target else ""
        subh = f'<div class="sub">{sub}</div>' if sub else ""
        return f'<a class="{cls}"{href}><div class="num">{value}</div><div class="lbl">{esc(label)}</div>{subh}{go}</a>'

    # ================= 01 DASHBOARD =================
    meter_idx = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[rating]
    meter = "".join(
        f'<span class="m-{c}{" on" if i <= meter_idx else ""}"></span>'
        for i, c in enumerate(["low", "med", "high", "crit"]))
    reasons = "".join(f"<li>{esc(x)}</li>" for x in risk_reasons(r))
    donut = svg_donut([("Cracked", cracked, RED), ("Blank password", blank, ORANGE), ("Not cracked", notc, GREY)])
    legend = (
        f'<div class="legend"><div><span class="sw" style="background:{_hexc(RED)}"></span>Cracked &mdash; <b>{cracked}</b> ({fmt_pct(cracked, total)})</div>'
        f'<div><span class="sw" style="background:{_hexc(ORANGE)}"></span>Blank password &mdash; <b>{blank}</b> ({fmt_pct(blank, total)})</div>'
        f'<div><span class="sw" style="background:#d8dce8"></span>Not cracked &mdash; <b>{notc}</b> ({fmt_pct(notc, total)})</div></div>')
    sevbox = "".join(
        f'<div class="sevbox sev-{SEV_CLASS[s]}"><b>{sev_counts.get(s, 0)}</b><span>{s}</span></div>' for s in SEV_ORDER)

    top1 = r["top_passwords"][0] if r["top_passwords"] else None
    ls = r["length_stats"]
    big = r["largest_reuse"]
    vweak = r["strength_breakdown"].get("Very Weak", 0)

    k_scope = "".join([
        card("Accounts analysed", total, f'{len(r["domain_breakdown"])} domain(s)', "accounts"),
        card("Unique NT hashes", r["unique_nt_hashes"], "distinct hashes in scope", "audit"),
        card("Passwords cracked", cracked, fmt_pct(cracked, total) + " of accounts", "accounts", alert=cracked > 0),
        card("Not cracked", notc, fmt_pct(notc, total) + " of accounts", "accounts", good=True),
        card("Blank passwords", blank, fmt_pct(blank, total) + " of accounts", "blanklm", alert=blank > 0, good=blank == 0),
        card("Disabled accts cracked", r["disabled_cracked"], f'{r["enabled_cracked"]} enabled cracked', "accounts"),
    ])
    k_risk = "".join([
        card("Privileged cracked", f'{len(r["admin_cracked"])}/{meta["admin_total"]}', f'{len(r["admin_blank"])} blank', "privileged",
             alert=bool(r["admin_cracked"]), good=not r["admin_cracked"]),
        card("Accounts reusing a password", r["reused_account_count"], f'{r["reuse_group_count"]} reuse group(s)', "reuse",
             alert=r["reused_account_count"] > 0),
        card("Largest reuse group", big["count"] if big else 0, "accounts share one password" if big else "none", "reuse"),
        card("Username = password", len(r["username_eq_password"]), fmt_pct(len(r["username_eq_password"]), cracked) + " of cracked",
             "ueq", alert=bool(r["username_eq_password"])),
        card("LM hashes stored", len(r["lm_present_accounts"]), fmt_pct(len(r["lm_present_accounts"]), total) + " of accounts", "blanklm",
             alert=bool(r["lm_present_accounts"])),
        card("Weak-pattern matches", len(r["weak_pattern_hits"]), fmt_pct(len(r["weak_pattern_hits"]), cracked) + " of cracked",
             "weak", alert=bool(r["weak_pattern_hits"])),
        card("History cycling", len(r["history_reuse"]), f'of {r["history_account_count"]} with history', "history"),
    ])
    k_pw = "".join([
        card("Unique passwords", r["unique_passwords"], f'across {cracked} cracked accounts', "top"),
        card("Average length", f'{ls["avg"]:.1f}', f'median {ls["median"]:g}', "length"),
        card("Shortest / longest", f'{ls["min"]} / {ls["max"]}', "characters", "length"),
        card(f'Below {r["min_length_flag"]}-char policy', r["short_password_count"], fmt_pct(r["short_password_count"], cracked) + " of cracked",
             "length", alert=r["short_password_count"] > 0),
        card("Very Weak passwords", vweak, fmt_pct(vweak, cracked) + " of cracked", "strength", alert=vweak > 0),
        card("Weak complexity (<3 classes)", r["below_complexity_count"], fmt_pct(r["below_complexity_count"], cracked) + " of cracked",
             "strength"),
        card("Most common password",
             f'<span class="pwd">{esc(top1[0])}</span>' if top1 else "&ndash;",
             f'used {top1[1]} time(s)' if top1 else "", "top"),
    ])

    dash = f"""
<div class="hero">
  <div class="panel riskcard"><h4>Overall risk rating</h4>
    <div class="big" style="color:{'#ff8497' if rating=='CRITICAL' else '#fff'}">{rating}</div>
    <div class="meter">{meter}</div><div class="meterlbl"><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>
    <ul>{reasons}</ul></div>
  <div class="panel"><h4>Account status</h4><div class="donutwrap">{donut}{legend}</div></div>
  <div class="panel"><h4>Findings by severity</h4><div class="sevrow">{sevbox}</div>
    <p class="muted" style="font-size:12.5px;margin:10px 0 0">{len(failing)} open finding(s) across {len(findings)} checks.
    <a href="#findings">Open the risk register &rarr;</a></p></div>
</div>
<div class="kgroup">Scope &amp; coverage</div><div class="cards">{k_scope}</div>
<div class="kgroup">Risk indicators</div><div class="cards">{k_risk}</div>
<div class="kgroup">Password statistics</div><div class="cards">{k_pw}</div>
<div class="two" style="margin-top:20px">
  <div class="panel"><h4>Strength of cracked passwords</h4>{hbars([(k, r["strength_breakdown"].get(k, 0), _hexc(STRENGTH_COLOR[k])) for k in STRENGTH_ORDER], cracked)}</div>
  <div class="panel"><h4>Top 5 recovered passwords</h4>{hbars([(p, c) for p, c in r["top_passwords"][:5]], cracked, "#ec1b3c", mask=True)}</div>
</div>"""

    # ================= 02 FINDINGS =================
    f_rows = []
    for f in findings:
        f_rows.append(
            "<tr>"
            f'<td class="mono nw" data-v="{f["id"]}"><b>{f["id"]}</b></td>'
            f'<td data-v="{SEV_ORDER.index(f["severity"])}"><span class="badge sev-{SEV_CLASS[f["severity"]]}">{f["severity"].upper()}</span></td>'
            f'<td>{esc(f["title"])}</td>'
            f'<td class="num" data-v="{f["count"]}"><b>{f["count"]}</b></td>'
            f'<td class="num" data-v="{pct(f["count"], f["base"]):.2f}">{f["pct"]}</td>'
            f'<td>{esc(f["recommendation"]) if f["count"] else "<span class=muted>No action required.</span>"}</td>'
            f'<td class="nw"><a href="#{f["anchor"]}">Evidence &rarr;</a></td></tr>')
    findings_body = (
        '<div class="sevlegend">' + "".join(
            f'<span><span class="badge sev-{SEV_CLASS[s]}">{s.upper()}</span> {sev_counts.get(s, 0)}</span>' for s in SEV_ORDER) + "</div><br>"
        + table_html([("ID", ""), ("Severity", ""), ("Finding", ""), ("Count", "num"), ("% of base", "num"),
                      ("Recommendation", ""), ("Trace", "")], "".join(f_rows), "findings-table")
        + '<p class="trace">% of base: accounts for account-level checks, cracked accounts for password-level checks. '
          'Click a column header to sort; the Evidence link jumps to the supporting data.</p>')

    # ================= 03 IMPACT =================
    comp = cracked + blank
    imp_cards = "".join([
        card("Accounts compromised", comp, fmt_pct(comp, total) + " of all accounts (cracked + blank)", "accounts", alert=comp > 0),
        card("Privileged exposure", len(r["admin_cracked"]) + len(r["admin_blank"]), "cracked or blank admin accounts", "privileged",
             alert=bool(r["admin_cracked"] or r["admin_blank"])),
        card("Max blast radius", big["count"] if big else 0, "accounts unlocked by one password", "reuse"),
        card("Accounts in reuse groups", r["reused_account_count"], fmt_pct(r["reused_account_count"], total) + " of accounts", "reuse"),
    ])
    imp_rows = "".join(
        "<tr>"
        f'<td class="mono"><a href="#findings">{f["id"]}</a></td>'
        f'<td><span class="badge sev-{SEV_CLASS[f["severity"]]}">{f["severity"].upper()}</span></td>'
        f'<td>{esc(f["title"])}</td><td class="num"><b>{f["count"]}</b></td><td>{esc(f["impact"])}</td></tr>'
        for f in failing)
    impact_body = (f'<div class="cards">{imp_cards}</div><h3 class="sub">Business impact per open finding</h3>'
                   + table_html([("ID", ""), ("Severity", ""), ("Finding", ""), ("Affected", "num"), ("What this means", "")],
                                imp_rows or "", "impact-table", sortable=False))

    # ================= 04 ACCOUNTS =================
    dom_rows = "".join(
        f'<tr><td><b>{esc(d["domain"])}</b></td><td class="num">{d["total"]}</td><td class="num">{d["cracked"]}</td>'
        f'<td class="num">{d["blank"]}</td><td class="num">{d["not_cracked"]}</td>'
        f'<td class="num" data-v="{pct(d["cracked"], d["total"]):.2f}">{fmt_pct(d["cracked"], d["total"])}</td></tr>'
        for d in r["domain_breakdown"])
    crow = []
    for x in sorted(r["cracked_accounts"], key=lambda z: (-z["is_admin"], z["username"].lower())):
        flags = []
        if x["is_admin"]:
            flags.append('<span class="badge priv">PRIV</span>')
        if x["is_disabled"]:
            flags.append('<span class="badge flag">DISABLED</span>')
        if pw_count.get(x["password"], 0) > 1:
            flags.append('<span class="badge flag">REUSED</span>')
        if x["full_name"] in ueq_set:
            flags.append('<span class="badge flag">USER=PASS</span>')
        if x["full_name"] in weak_map:
            flags.append(f'<span class="badge flag" title="{esc(weak_map[x["full_name"]])}">WEAK PATTERN</span>')
        crow.append(
            "<tr>"
            f'<td>{esc(x["full_name"])}</td><td class="pwd">{esc(x["password"])}</td>'
            f'<td class="num">{x["length"]}</td>'
            f'<td data-v="{STRENGTH_ORDER.index(x["bucket"])}"><span class="badge {bucket_class(x["bucket"])}">{esc(x["bucket"])}</span></td>'
            f'<td class="num">{x["complexity_score"]}/4</td>'
            f'<td class="num">{pw_count.get(x["password"], 1)}</td><td>{" ".join(flags)}</td></tr>')
    accounts_body = (
        '<h3 class="sub" style="margin-top:0">Per-domain breakdown</h3>'
        + table_html([("Domain", ""), ("Accounts", "num"), ("Cracked", "num"), ("Blank", "num"), ("Not cracked", "num"), ("Crack rate", "num")],
                     dom_rows, "domain-table")
        + '<h3 class="sub">Cracked accounts</h3>'
          '<div class="filterbar"><input class="filter" id="cr-f" type="text" placeholder="Filter by account, password, flag&hellip;" '
          "oninput=\"filterTable('cr-f','cracked-table','cr-c')\"><span class='rowcount' id='cr-c'>"
          f'Showing {len(crow)} of {len(crow)}</span></div>'
        + table_html([("Account", ""), ("Password", ""), ("Length", "num"), ("Strength", ""), ("Complexity", "num"),
                      ("Times used", "num"), ("Flags", "")], "".join(crow), "cracked-table"))

    # ================= 05 STRENGTH =================
    comp_rows = "".join(
        f'<tr><td>{esc(l)}</td><td class="num">{v}</td><td class="num" data-v="{pct(v, cracked):.2f}">{fmt_pct(v, cracked)}</td></tr>'
        for l, v in r["composition"])
    cx_items = [(f"{k} of 4 classes", v, "#204399") for k, v in r["complexity_distribution"]]
    strength_body = (
        '<div class="two"><div><h3 class="sub" style="margin-top:0">Strength buckets</h3>'
        + hbars([(k, r["strength_breakdown"].get(k, 0), _hexc(STRENGTH_COLOR[k])) for k in STRENGTH_ORDER], cracked)
        + '<h3 class="sub">Complexity score (character classes used)</h3>' + hbars(cx_items, cracked)
        + '</div><div><h3 class="sub" style="margin-top:0">Composition statistics</h3>'
        + table_html([("Characteristic", ""), ("Passwords", "num"), ("% of cracked", "num")], comp_rows, "comp-table")
        + '</div></div><p class="trace">Buckets: Very Weak = &lt;8 chars or 1 class; Weak = &lt;12 chars &amp; 2 classes; '
          'Moderate = &lt;12 chars &amp; 3+ classes, or 12+ chars &amp; 2 classes; Stronger = everything else. '
          'Every password here was recovered, so even "Stronger" is a relative label.</p>')

    # ================= 06 LENGTH =================
    ld = r["length_distribution"]
    cum = 0
    len_rows = []
    for k in sorted(ld):
        cum += ld[k]
        len_rows.append(
            f'<tr><td data-v="{k}">{k}{"+" if k == 16 else ""}</td><td class="num">{ld[k]}</td>'
            f'<td class="num">{fmt_pct(ld[k], cracked)}</td><td class="num">{fmt_pct(cum, cracked)}</td></tr>')
    len_chart = svg_bars([f"{k}+" if k == 16 else str(k) for k in sorted(ld)], [ld[k] for k in sorted(ld)], BLUE)
    avg_s = f'{ls["avg"]:.1f}'
    med_s = f'{ls["median"]:g}'
    under_s = f'under {r["min_length_flag"]} chars'
    length_body = (
        '<div class="cards" style="margin-bottom:16px">'
        + card("Minimum", ls["min"], "characters") + card("Maximum", ls["max"], "characters")
        + card("Average", avg_s, "characters") + card("Median", med_s, "characters")
        + card("Below policy", r["short_password_count"], under_s, alert=r["short_password_count"] > 0)
        + '</div>'
        + f'<div class="panel">{len_chart}</div><br>'
        + table_html([("Length", "num"), ("Passwords", "num"), ("% of cracked", "num"), ("Cumulative %", "num")],
                     "".join(len_rows), "len-table"))

    # ================= 07 TOP =================
    top_rows = []
    for i, (p, c) in enumerate(r["top_passwords"][:meta["top_n"]], start=1):
        tr = next((x for x in r["cracked_accounts"] if x["password"] == p), None)
        top_rows.append(
            f'<tr><td class="num">{i}</td><td class="pwd">{esc(p)}</td><td class="num"><b>{c}</b></td>'
            f'<td class="num" data-v="{pct(c, cracked):.2f}">{fmt_pct(c, cracked)}</td>'
            f'<td class="num">{len(p)}</td><td><span class="badge {bucket_class(tr["bucket"])}">{esc(tr["bucket"])}</span></td></tr>'
            if tr else "")
    top_body = table_html([("Rank", "num"), ("Password", ""), ("Occurrences", "num"), ("% of cracked", "num"), ("Length", "num"),
                           ("Strength", "")], "".join(top_rows), "top-table")

    # ================= 08 PRIVILEGED =================
    if meta["admin_total"] == 0:
        priv_body = '<p class="empty-state">No privileged-account list was supplied (<code>--admins</code>).</p>'
    else:
        arows = "".join(
            "<tr>"
            f'<td>{esc(x["full_name"])} <span class="badge priv">PRIV</span></td><td class="pwd">{esc(x["password"])}</td>'
            f'<td class="num">{x["length"]}</td><td><span class="badge {bucket_class(x["bucket"])}">{esc(x["bucket"])}</span></td>'
            f'<td class="num">{pw_count.get(x["password"], 1)}</td></tr>' for x in r["admin_cracked"])
        nf = ", ".join(r["admin_not_found"])
        priv_body = (
            '<div class="cards" style="margin-bottom:16px">'
            + card("Listed", meta["admin_total"], "usernames supplied") + card("Found in dump", len(r["admin_found"]), "matched an NTDS account")
            + card("Cracked", len(r["admin_cracked"]), "recovered passwords", alert=bool(r["admin_cracked"]), good=not r["admin_cracked"])
            + card("Blank", len(r["admin_blank"]), "empty password", alert=bool(r["admin_blank"]), good=not r["admin_blank"])
            + '</div>'
            + table_html([("Account", ""), ("Password", ""), ("Length", "num"), ("Strength", ""), ("Times used", "num")], arows, "priv-table")
            + (f'<p class="trace">Listed but not found in the NTDS dump (check spelling): {esc(nf)}</p>' if nf else ""))

    # ================= 09 REUSE =================
    if not r["reuse_groups"]:
        reuse_body = '<p class="empty-state">No password reuse detected across cracked accounts.</p>'
    else:
        gs = []
        for g in r["reuse_groups"][:300]:
            tr = next((x for x in r["cracked_accounts"] if x["password"] == g["password"]), None)
            sb = f'<span class="badge {bucket_class(tr["bucket"])}">{esc(tr["bucket"])}</span>' if tr else ""
            gs.append('<details class="group"><summary>'
                      f'<b class="pwd">{esc(g["password"])}</b><span class="badge flag">{g["count"]} accounts</span>{sb}</summary>'
                      f'<div class="members">{esc(", ".join(g["usernames"]))}</div></details>')
        note = (f'<p class="trace">Showing the 300 largest of {len(r["reuse_groups"])} groups; full list in the CSV / JSON output.</p>'
                if len(r["reuse_groups"]) > 300 else "")
        reuse_body = (
            '<div class="cards" style="margin-bottom:16px">'
            + card("Reuse groups", r["reuse_group_count"], "distinct reused passwords", alert=True)
            + card("Accounts affected", r["reused_account_count"], fmt_pct(r["reused_account_count"], total) + " of accounts")
            + card("Largest group", big["count"], "accounts, one password") + '</div>'
            '<div class="filterbar"><input class="filter" id="ru-f" type="text" placeholder="Filter groups by password or account&hellip;" '
            "oninput=\"filterGroups('ru-f','reuse-wrap')\"></div>"
            f'<div id="reuse-wrap">{"".join(gs)}</div>{note}')

    # ================= 10 UEQ / 11 WEAK =================
    ueq_rows = "".join(f'<tr><td>{esc(x["full_name"])}</td><td class="pwd">{esc(x["password"])}</td></tr>' for x in r["username_eq_password"])
    ueq_body = table_html([("Account", ""), ("Password", "")], ueq_rows, "ueq-table")
    wc = collections.Counter(h["pattern_label"] for h in r["weak_pattern_hits"])
    weak_rows = "".join(
        f'<tr><td>{esc(h["full_name"])}</td><td class="pwd">{esc(h["password"])}</td><td>{esc(h["pattern_label"])}</td></tr>'
        for h in r["weak_pattern_hits"])
    weak_body = ('<h3 class="sub" style="margin-top:0">Matches by pattern</h3>'
                 + hbars([(k, v) for k, v in wc.most_common()], cracked, "#e07a1f")
                 + '<h3 class="sub">All matches</h3>'
                 + table_html([("Account", ""), ("Password", ""), ("Pattern", "")], weak_rows, "weak-table"))

    # ================= 12 HISTORY =================
    if not r["history_reuse"]:
        hist_body = '<p class="empty-state">No password-history file supplied (<code>--history</code>), or no cyclical reuse detected.</p>'
    else:
        hrows = "".join(
            f'<tr><td>{esc(h["username"])}</td><td class="num">{h["recovered_count"]}</td>'
            f'<td>{" &rarr; ".join(f"<span class=pwd>{esc(p)}</span>" for p in h["passwords"])}</td></tr>' for h in r["history_reuse"])
        hist_body = (f'<p class="trace">{r["history_account_count"]} account(s) had history entries; '
                     f'{len(r["history_reuse"])} had two or more recovered passwords.</p>'
                     + table_html([("Account", ""), ("Recovered", "num"), ("Passwords (oldest \u2192 newest)", "")], hrows, "hist-table"))

    # ================= 13 BLANK / LM =================
    bl = "".join(f"<li>{esc(u)}</li>" for u in r["empty_password_accounts"]) or '<li class="muted">None</li>'
    ll = "".join(f"<li>{esc(u)}</li>" for u in r["lm_present_accounts"]) or '<li class="muted">None</li>'
    blank_body = (f'<div class="two"><div><h3 class="sub" style="margin-top:0">Blank / empty passwords ({blank})</h3><ul class="scroll">{bl}</ul></div>'
                  f'<div><h3 class="sub" style="margin-top:0">LM hash present ({len(r["lm_present_accounts"])})</h3><ul class="scroll">{ll}</ul></div></div>')

    # ================= 14 AUDIT TRAIL =================
    inp = meta.get("inputs", [])
    in_rows = "".join(
        f'<tr><td>{esc(i["role"])}</td><td class="mono">{esc(i["path"])}</td><td class="num">{i["size"]:,}</td>'
        f'<td class="num">{i["lines"]:,}</td><td class="mono" style="font-size:11.5px;word-break:break-all">{esc(i["sha256"])}</td></tr>'
        for i in inp)
    ps = meta.get("parse_stats", {})
    nt, ck = ps.get("ntds", {}), ps.get("cracked", {})
    kv = [
        ("Tool", f"NullPAT v{VERSION}"),
        ("Author", f"{AUTHOR_NAME} ({AUTHOR_HANDLE})"),
        ("Report generated", r["generated_at"]),
        ("Target / label", meta.get("target_name") or "Unspecified"),
        ("Command line", meta.get("command", "")),
        ("Python / platform", meta.get("platform", "")),
        ("Minimum length policy", f'{r["min_length_flag"]} characters'),
        ("Computer accounts", "included" if meta.get("include_computers") else f'excluded ({nt.get("computers_excluded", 0)} skipped)'),
        ("Custom company terms", ", ".join(meta.get("company_terms", [])) or "none"),
        ("Privileged list / disabled list", f'{meta["admin_total"]} / {r["disabled_total"]} usernames'),
    ]
    kv_html = "".join(f'<tr><td>{esc(k)}</td><td class="mono" style="word-break:break-all">{esc(v)}</td></tr>' for k, v in kv)
    pstats = [
        ("NTDS lines read", nt.get("lines", 0)), ("NTDS entries parsed", nt.get("parsed", 0)), ("NTDS lines skipped (unparseable)", nt.get("skipped", 0)),
        ("NTDS duplicate entries dropped", nt.get("duplicates", 0)), ("History entries found", nt.get("history_entries", 0)),
        ("Cracked-list lines read", ck.get("lines", 0)), ("Valid hash:password pairs", ck.get("valid", 0)),
        ("Duplicate hashes in cracked list", ck.get("duplicates", 0)), ("Invalid / skipped lines", ck.get("invalid", 0)),
        ("$HEX[...] passwords decoded", ck.get("hex_decoded", 0)),
    ]
    ps_html = "".join(f'<tr><td>{esc(k)}</td><td class="num">{v:,}</td></tr>' for k, v in pstats)
    wp = "".join(f'<tr><td class="mono">{esc(p)}</td><td>{esc(l)}</td></tr>' for p, l in meta.get("weak_patterns", []))
    sev_rules = ("<tr><td>CRITICAL</td><td>crack rate &ge; 30% <b>or</b> any privileged account cracked</td></tr>"
                 "<tr><td>HIGH</td><td>crack rate &ge; 15% <b>or</b> &ge; 10 accounts reusing passwords</td></tr>"
                 "<tr><td>MEDIUM</td><td>crack rate &ge; 5%</td></tr><tr><td>LOW</td><td>otherwise</td></tr>")
    audit_body = (
        '<h3 class="sub" style="margin-top:0">Run details</h3><div class="tablewrap"><table class="kv"><tbody>' + kv_html + '</tbody></table></div>'
        '<h3 class="sub">Input files (integrity)</h3>'
        + table_html([("Role", ""), ("Path", ""), ("Bytes", "num"), ("Lines", "num"), ("SHA-256", "")], in_rows, sortable=False)
        + '<p class="trace">Re-hash the original inputs and compare the SHA-256 values to prove this report came from those exact files.</p>'
        '<div class="two"><div><h3 class="sub">Parsing statistics</h3><div class="tablewrap"><table class="kv"><tbody>' + ps_html + '</tbody></table></div></div>'
        '<div><h3 class="sub">Risk-rating rules</h3>' + table_html([("Rating", ""), ("Trigger", "")], sev_rules, sortable=False) + '</div></div>'
        '<h3 class="sub">Weak-pattern rules applied</h3>' + table_html([("Regex (case-insensitive)", ""), ("Label", "")], wp, sortable=False)
        + '<h3 class="sub">Finding IDs</h3><p class="trace">Finding IDs (NP-01 &hellip; NP-' + f'{len(findings):02d}' + ') are stable between runs of the same '
          'tool version, so they can be quoted in tickets and re-test reports.</p>')

    bodies = {
        "overview": (dash, "At-a-glance results. Every card is a link &mdash; click it to jump to the evidence behind the number."),
        "findings": (findings_body, "Each check has a stable ID, a severity, a count and a recommendation. Passing checks are shown for completeness."),
        "impact": (impact_body, "What the findings mean in practice for the organisation."),
        "accounts": (accounts_body, "Crack rate per domain and every account whose NT hash matched the cracked-password list."),
        "strength": (strength_body, "How the recovered passwords are built &mdash; used to prioritise policy changes."),
        "length": (length_body, "Length of each cracked password (16 = 16 or more characters)."),
        "top": (top_body, f'The {meta["top_n"]} most common recovered passwords by number of accounts using them.'),
        "privileged": (priv_body, "Accounts supplied via <code>--admins</code>, cross-referenced against the cracked set."),
        "reuse": (reuse_body, "Passwords shared by more than one account &mdash; compromise of one compromises all."),
        "ueq": (ueq_body, "Accounts whose password is identical to their own username."),
        "weak": (weak_body, "Cracked passwords matching common weak patterns (seasons, 'password', keyboard walks and custom terms)."),
        "history": (hist_body, "Accounts recycling a small set of passwords across their history (requires <code>--history</code>)."),
        "blanklm": (blank_body, "Accounts with no password and accounts still storing the legacy LM hash."),
        "audit": (audit_body, "Everything needed to reproduce and verify this report."),
    }
    sections_html = "".join(sec(k, *bodies[k]) for k in keys)

    pills = {
        "overview": str(total), "findings": str(len(failing)), "impact": str(cracked + blank),
        "accounts": str(cracked), "strength": str(cracked), "length": f'{ls["avg"]:.1f}',
        "top": str(len(r["top_passwords"])), "privileged": f'{len(r["admin_cracked"])}/{meta["admin_total"]}',
        "reuse": str(r["reuse_group_count"]), "ueq": str(len(r["username_eq_password"])),
        "weak": str(len(r["weak_pattern_hits"])), "history": str(len(r["history_reuse"])),
        "blanklm": str(blank + len(r["lm_present_accounts"])), "audit": "log",
    }
    toc = "".join(
        f'<a href="#{k}" data-sec="{k}" title="{esc(S[k][0])}"><span class="n">{i+1:02d}</span>{esc(S[k][0])}'
        f'<span class="pill">{esc(pills[k])}</span></a>' for i, k in enumerate(keys))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="author" content="{AUTHOR_NAME} ({AUTHOR_HANDLE})">
<title>{esc(title)}</title>
<style>{HTML_CSS}</style>
</head>
<body>
<header class="masthead" id="top">
  <div class="mast-top">
    <div>
      <div class="brand"><span class="mark">Null<span class="pat">PAT</span></span>
        <span class="risk-badge" style="background:{rating_color}">{rating} RISK</span></div>
      <div class="tag">Null-Session Password Audit Tool &middot; password audit report &middot; v{VERSION}</div>
    </div>
    <div class="author"><div>Tool built by</div><div class="by">{AUTHOR_NAME} ({AUTHOR_HANDLE})</div>{author_links_html()}</div>
  </div>
  <div class="meta">
    <div>Target: <b>{esc(meta.get("target_name") or "Unspecified domain")}</b></div>
    <div>Generated: <b>{esc(r["generated_at"])}</b></div>
    <div>Accounts in scope: <b>{total}</b></div>
    <div>Cracked: <b>{cracked} ({r["cracked_pct"]:.1f}%)</b></div>
    <div>Open findings: <b>{len(failing)}</b></div>
  </div>
</header>
<div class="layout">
<aside class="sidebar">
  <div><div class="navtitle">Report sections</div><nav class="toc">{toc}</nav></div>
  <div class="authorcard"><b>{AUTHOR_NAME} ({AUTHOR_HANDLE})</b><span class="muted">Creator of NullPAT</span>
    <a href="{AUTHOR_LINKEDIN}" target="_blank" rel="noopener noreferrer">LinkedIn &mdash; /in/budsec</a>
    <a href="{AUTHOR_GITHUB}" target="_blank" rel="noopener noreferrer">GitHub &mdash; BuddySecurity</a>
    <a href="{AUTHOR_YOUTUBE}" target="_blank" rel="noopener noreferrer">YouTube &mdash; @BudSec</a></div>
</aside>
<main>
  <div class="toolbar">
    <button onclick="expandAll(true)">Expand all</button>
    <button onclick="expandAll(false)">Collapse all</button>
    <button onclick="toggleReveal(this)">Reveal passwords</button>
    <button onclick="window.print()">Print / PDF</button>
    <span class="spacer"></span>
    <span class="hint">Passwords are blurred by default &mdash; take care when screen-sharing.</span>
  </div>
  {sections_html}
  <footer class="disclaimer"><b>Handle this report as client-confidential data.</b>
    It contains cleartext passwords recovered during an authorized engagement. Store it encrypted,
    restrict access to the engagement team, and delete it once remediation reporting is complete.</footer>
  <footer class="credit">
    <div><b>NullPAT v{VERSION}</b> &mdash; built by <b>{AUTHOR_NAME} ({AUTHOR_HANDLE})</b></div>
    {author_links_html()}
  </footer>
</main>
</div>
<button class="btn" id="totop" onclick="window.scrollTo({{top:0,behavior:'smooth'}})">&uarr; Top</button>
<script>{HTML_JS}</script>
</body>
</html>"""



# --------------------------------------------------------------------------
# Other output formats
# --------------------------------------------------------------------------

def write_json(results, path):
    serializable = dict(results)
    with open(path, "w") as fh:
        json.dump(serializable, fh, indent=2, default=str)


def write_csv(results, out_dir):
    def dump(name, fieldnames, rows):
        p = os.path.join(out_dir, name)
        with open(p, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in fieldnames})
        return p

    paths = []
    paths.append(dump("cracked_accounts.csv",
                       ["full_name", "password", "length", "bucket", "complexity_score",
                        "is_admin", "is_disabled"],
                       results["cracked_accounts"]))
    paths.append(dump("password_reuse.csv", ["password", "count", "usernames"],
                       [{**g, "usernames": "; ".join(g["usernames"])} for g in results["reuse_groups"]]))
    paths.append(dump("weak_pattern_hits.csv", ["full_name", "password", "pattern_label"],
                       results["weak_pattern_hits"]))
    paths.append(dump("username_eq_password.csv", ["full_name", "password"],
                       results["username_eq_password"]))

    summary_path = os.path.join(out_dir, "summary.csv")
    with open(summary_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "value"])
        w.writerow(["total_accounts", results["total_accounts"]])
        w.writerow(["cracked_count", results["cracked_count"]])
        w.writerow(["cracked_pct", f'{results["cracked_pct"]:.2f}'])
        w.writerow(["blank_passwords", len(results["empty_password_accounts"])])
        w.writerow(["lm_hashes_present", len(results["lm_present_accounts"])])
        w.writerow(["accounts_reusing_password", results["reused_account_count"]])
        w.writerow(["privileged_accounts_cracked", len(results["admin_cracked"])])
        w.writerow(["risk_rating", risk_rating(results)])
        w.writerow(["tool", f"NullPAT v{VERSION} by {AUTHOR_NAME} ({AUTHOR_HANDLE})"])
    paths.append(summary_path)
    return paths


def write_txt(results, path):
    rating = risk_rating(results)
    lines = []
    lines.append("NULLPAT PASSWORD AUDIT REPORT")
    lines.append("=" * 60)
    lines.append(f'Generated:            {results["generated_at"]}')
    lines.append(f'Overall risk rating:  {rating}')
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 60)
    lines.append(f'Accounts analyzed:              {results["total_accounts"]}')
    lines.append(f'Cracked:                        {results["cracked_count"]} ({results["cracked_pct"]:.1f}%)')
    lines.append(f'Blank passwords:                {len(results["empty_password_accounts"])}')
    lines.append(f'LM hashes present:               {len(results["lm_present_accounts"])}')
    lines.append(f'Accounts reusing a password:     {results["reused_account_count"]}')
    lines.append(f'Privileged accounts cracked:     {len(results["admin_cracked"])}/{results["admin_total"]}')
    lines.append(f'Username == password:            {len(results["username_eq_password"])}')
    lines.append(f'Weak-pattern matches:            {len(results["weak_pattern_hits"])}')
    lines.append("")
    lines.append("TOP PASSWORDS")
    lines.append("-" * 60)
    for p, c in results["top_passwords"][:25]:
        lines.append(f"  {c:>5}  {p}")
    lines.append("")
    lines.append("PASSWORD REUSE GROUPS")
    lines.append("-" * 60)
    for g in results["reuse_groups"][:50]:
        lines.append(f'  "{g["password"]}" -> {g["count"]} accounts: {", ".join(g["usernames"])}')
    lines.append("")
    lines.append("PRIVILEGED ACCOUNTS CRACKED")
    lines.append("-" * 60)
    for r in results["admin_cracked"]:
        lines.append(f'  {r["full_name"]:<30} {r["password"]}')
    lines.append("")
    lines.append("-" * 60)
    lines.append(f"Built by {AUTHOR_NAME} ({AUTHOR_HANDLE})")
    lines.append(f"  LinkedIn: {AUTHOR_LINKEDIN}")
    lines.append(f"  GitHub  : {AUTHOR_GITHUB}")
    lines.append(f"  YouTube : {AUTHOR_YOUTUBE}")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------
# Example commands (--example-commands)
# --------------------------------------------------------------------------

EXAMPLE_COMMANDS = [
    ("1. QUICK START  (minimum required flags)",
     "Only --ntds and --cracked are required. Writes ./nullpat_report/nullpat_report.html",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile",
     ]),
    ("2. TRY IT ON THE BUNDLED SAMPLE DATA",
     "Synthetic fixtures shipped in sample_data/ - safe for demos and for testing your install.",
     [
         "python3 nullpat.py --ntds sample_data/ntds_sample.txt --cracked sample_data/cracked_sample.txt",
         "python3 nullpat.py --ntds sample_data/ntds_history_sample.txt --cracked sample_data/cracked_sample.txt \\\n"
         "    --admins sample_data/admins_sample.txt --history sample_data/ntds_history_sample.txt \\\n"
         "    --target-name \"Demo Corp\" --format all",
     ]),
    ("3. PRIVILEGED ACCOUNT EXPOSURE  (--admins)",
     "One username per line (no DOMAIN\\ prefix). Cracked admins force a CRITICAL rating.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --admins domain_admins.txt",
         "# build the admin list from a net group export:\n"
         "net group \"Domain Admins\" /domain | findstr /v \"command\" > domain_admins.txt",
     ]),
    ("4. DISABLED ACCOUNTS  (--disabled)",
     "Flagged in the cracked-accounts table and counted separately - not excluded from statistics.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --disabled disabled_users.txt",
     ]),
    ("5. PASSWORD HISTORY / CYCLING  (--history)",
     "Use a dump taken with secretsdump.py -history. Detects users rotating through the same few passwords.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --history ntds_history.txt",
     ]),
    ("6. COMPANY / CUSTOM WEAK PATTERNS  (--company-name, repeatable)",
     "Any password containing the term is flagged as a weak pattern. Repeat the flag for multiple terms.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --company-name Contoso",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile \\\n"
         "    --company-name Contoso --company-name Widgets --company-name Spring2024",
     ]),
    ("7. PASSWORD POLICY LENGTH  (--min-length)",
     "Sets the 'below policy' threshold used in the dashboard, findings and length section (default 8).",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --min-length 12",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --min-length 14",
     ]),
    ("8. COMPUTER ACCOUNTS  (--include-computers)",
     "Machine accounts (names ending in $) are excluded by default.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --include-computers",
     ]),
    ("9. TOP-N PASSWORDS  (--top)",
     "How many entries appear in the 'Top Recovered Passwords' section (default 25).",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --top 50",
     ]),
    ("10. OUTPUT FORMATS & LOCATION  (-f / --format, -o / --output-dir)",
     "html (default), csv, json, txt or all. Output directory is created if missing.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f html",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f csv  -o ./csv_out",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f json -o ./json_out",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f txt  -o ./txt_out",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f all  -o ./full_report",
     ]),
    ("11. LABEL THE REPORT  (--target-name)",
     "Client / engagement name shown in the HTML masthead, page title and audit trail.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile \\\n"
         "    --target-name \"Contoso Corp - Q4 Domain Password Audit\"",
     ]),
    ("12. SCRIPTING / CI / LOGGING  (--quiet, --no-banner, --no-color)",
     "Quiet mode prints only the summary. Exit code is 0 on success, 2 if an input file is missing.",
     [
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --quiet --no-color",
         "python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile --no-banner --no-color > run.log",
         "NO_COLOR=1 python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile -f json --quiet",
         "# pull a single metric out of the JSON report:\n"
         "python3 -c \"import json;print(json.load(open('nullpat_report/nullpat_report.json'))['cracked_pct'])\"",
     ]),
    ("13. PREPARING THE INPUTS  (before running NullPAT)",
     "NullPAT never cracks anything. Use these only on systems you are authorized to assess.",
     [
         "# NTDS dump with password history (impacket):\n"
         "secretsdump.py -ntds ntds.dit -system SYSTEM -history LOCAL -outputfile corp",
         "# unique NT hashes for your cracking rig:\n"
         "cut -d: -f4 corp.ntds | sort -u > ntlm_hashes.txt",
         "# export already-cracked hashes as hash:password for --cracked ($HEX[...] is decoded for you):\n"
         "hashcat -m 1000 --show --potfile-path hashcat.potfile ntlm_hashes.txt > cracked.txt",
     ]),
    ("14. FULL ENGAGEMENT EXAMPLE  (every aspect combined)",
     "Everything at once: privileged + disabled flags, history, company terms, policy, all formats.",
     [
         "python3 nullpat.py \\\n"
         "    --ntds corp.ntds \\\n"
         "    --cracked cracked.txt \\\n"
         "    --history corp_history.ntds \\\n"
         "    --admins domain_admins.txt \\\n"
         "    --disabled disabled_users.txt \\\n"
         "    --company-name Contoso --company-name Widgets \\\n"
         "    --min-length 12 \\\n"
         "    --top 50 \\\n"
         "    --target-name \"Contoso Corp - Q4 Domain Password Audit\" \\\n"
         "    --output-dir ./contoso_report \\\n"
         "    --format all",
     ]),
    ("15. OPEN & HANDLE THE REPORT",
     "The HTML report is a single self-contained file. Passwords are blurred until you click 'Reveal passwords'.",
     [
         "xdg-open ./nullpat_report/nullpat_report.html      # Linux",
         "open ./nullpat_report/nullpat_report.html          # macOS",
         "start .\\nullpat_report\\nullpat_report.html         # Windows",
         "# encrypt the report folder once you are done:\n"
         "tar czf - nullpat_report | gpg -c -o nullpat_report.tar.gz.gpg && shred -u nullpat_report/*",
     ]),
    ("16. HELP",
     "",
     [
         "python3 nullpat.py --help",
         "python3 nullpat.py --example-commands",
         "python3 nullpat.py --version",
     ]),
]


def print_example_commands(pal: Palette):
    print()
    print(pal.bold("  NULLPAT - EXAMPLE COMMANDS"))
    print(pal.dim("  " + "\u2500" * 66))
    print(pal.dim("  Replace the file names with your own. On Windows use 'python' instead of 'python3'."))
    print(pal.dim("  Flags can be combined freely; only --ntds and --cracked are required."))
    for title, desc, cmds in EXAMPLE_COMMANDS:
        print()
        print("  " + pal.accent(title))
        if desc:
            print("  " + pal.dim(desc))
        for cmd in cmds:
            print()
            first_cmd_line = True
            for line in cmd.splitlines():
                if line.lstrip().startswith("#"):
                    print("    " + pal.dim(line))
                elif first_cmd_line:
                    print("    " + pal.info("$ ") + line)
                    first_cmd_line = False
                else:
                    print("    " + line)
    print()
    print(pal.dim("  " + "\u2500" * 66))
    print("  " + pal.rgb(f"Built by {AUTHOR_NAME} ({AUTHOR_HANDLE})", BLUE, bold=True))
    print(pal.dim(f"  LinkedIn: {AUTHOR_LINKEDIN}"))
    print(pal.dim(f"  GitHub  : {AUTHOR_GITHUB}"))
    print(pal.dim(f"  YouTube : {AUTHOR_YOUTUBE}"))
    print()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Raw epilog formatting, and only shows '(default: X)' when X is meaningful."""

    def _get_help_string(self, action):
        text = action.help or ""
        if "%(default)" in text or action.default in (None, False, [], "", argparse.SUPPRESS):
            return text
        return text + " (default: %(default)s)"


HELP_EPILOG = f"""
quick examples:
  python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile
  python3 nullpat.py --ntds ntds.dit.txt --cracked cracked.txt --admins admins.txt -f all -o ./report
  python3 nullpat.py --ntds ntds.dit.txt --cracked cracked.txt --history hist.txt \\
      --company-name Contoso --min-length 12 --target-name "Contoso Q4 Audit"

  >>> run  python3 nullpat.py --example-commands  for the full list of example
      commands covering every flag and workflow.

built by {AUTHOR_NAME} ({AUTHOR_HANDLE})
  LinkedIn : {AUTHOR_LINKEDIN}
  GitHub   : {AUTHOR_GITHUB}
  YouTube  : {AUTHOR_YOUTUBE}
"""


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="nullpat",
        description="NullPAT - correlate a cracked-password list against an NTDS dump and "
                    "produce an audit-ready report (a modernized DPAT).",
        formatter_class=_HelpFormatter,
        epilog=HELP_EPILOG,
    )
    g_in = p.add_argument_group("input files")
    g_in.add_argument("--ntds", help="[required] secretsdump.py-style NTDS dump file")
    g_in.add_argument("--cracked", help="[required] hash:password cracked list (hashcat potfile or similar)")
    g_in.add_argument("--history", help="NTDS dump including *_historyN accounts, for reuse-over-time analysis")
    g_in.add_argument("--admins", help="file of privileged usernames, one per line")
    g_in.add_argument("--disabled", help="file of disabled usernames to flag (not excluded from stats)")

    g_an = p.add_argument_group("analysis options")
    g_an.add_argument("--company-name", action="append", default=[],
                      help="flag passwords containing this string as a weak pattern (repeatable)")
    g_an.add_argument("--include-computers", action="store_true", help="include computer ($) accounts in the analysis")
    g_an.add_argument("--min-length", type=int, default=8,
                      help="password-policy minimum length used for the 'below policy' flag")
    g_an.add_argument("--top", type=int, default=25, help="how many top passwords to list")

    g_out = p.add_argument_group("output options")
    g_out.add_argument("-o", "--output-dir", default="./nullpat_report", help="directory to write the report into")
    g_out.add_argument("-f", "--format", choices=["html", "csv", "json", "txt", "all"], default="html",
                       help="report output format")
    g_out.add_argument("--target-name", default="", help="label for the client/domain, shown in the report")

    g_ui = p.add_argument_group("display & help")
    g_ui.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    g_ui.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    g_ui.add_argument("--quiet", action="store_true", help="suppress progress output, print only the summary")
    g_ui.add_argument("--example-commands", action="store_true",
                      help="print example commands covering every flag and workflow, then exit")
    g_ui.add_argument("--version", action="version", version=f"NullPAT {VERSION} by {AUTHOR_NAME} ({AUTHOR_HANDLE})")
    return p


def file_info(role, path):
    import hashlib
    h = hashlib.sha256()
    lines = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            lines += chunk.count(b"\n")
    return {"role": role, "path": os.path.abspath(path), "size": os.path.getsize(path),
            "lines": lines, "sha256": h.hexdigest()}


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    pal = Palette(color_enabled(args.no_color))

    if args.example_commands:
        if not args.no_banner:
            print()
            print(render_banner(pal, sub="modernized DPAT \u2014 audit-grade password reporting"))
        print_example_commands(pal)
        return 0

    if not args.ntds or not args.cracked:
        parser.error("--ntds and --cracked are required "
                     "(run with --example-commands to see usage examples)")

    status = Status(pal if not args.quiet else Palette(False))

    if not args.no_banner and not args.quiet:
        print()
        print(render_banner(pal, sub="modernized DPAT \u2014 audit-grade password reporting"))
        print()

    for required in (args.ntds, args.cracked):
        if not os.path.isfile(required):
            status.bad(f"File not found: {required}")
            return 2
    for optional in (args.history, args.admins, args.disabled):
        if optional and not os.path.isfile(optional):
            status.bad(f"File not found: {optional}")
            return 2

    t0 = time.time()
    parse_stats = {"ntds": {}, "cracked": {}, "history": {}}
    status.step(f"Loading NTDS dump: {args.ntds}")
    accounts, history = parse_ntds(args.ntds, status, include_computers=args.include_computers,
                                   stats=parse_stats["ntds"])
    status.ok(f"Parsed {len(accounts)} accounts"
              f'{" (history entries found)" if history else ""}')

    status.step(f"Loading cracked-password list: {args.cracked}")
    cracked_hashes = parse_cracked_file(args.cracked, status, stats=parse_stats["cracked"])
    status.ok(f"Loaded {len(cracked_hashes)} cracked hashes")

    history_accounts = {}
    if args.history:
        status.step(f"Loading password-history dump: {args.history}")
        _, history_accounts = parse_ntds(args.history, status, include_computers=True,
                                         stats=parse_stats["history"])
        status.ok(f"Found history for {len(history_accounts)} accounts")
    admins = load_name_list(args.admins)
    disabled = load_name_list(args.disabled)
    if args.admins:
        status.ok(f"Loaded {len(admins)} privileged usernames")
    if args.disabled:
        status.ok(f"Loaded {len(disabled)} disabled usernames")

    company_patterns = [(re.escape(c), f"contains company name '{c}'") for c in args.company_name if c]

    status.step("Analyzing accounts\u2026")
    results = analyze(accounts, history_accounts or history, cracked_hashes, admins, disabled,
                      DEFAULT_WEAK_PATTERNS, args.min_length, company_patterns, status)

    inputs = [file_info("NTDS dump", args.ntds), file_info("Cracked list", args.cracked)]
    if args.history:
        inputs.append(file_info("History dump", args.history))
    if args.admins:
        inputs.append(file_info("Privileged list", args.admins))
    if args.disabled:
        inputs.append(file_info("Disabled list", args.disabled))

    import platform
    meta = {
        "top_n": args.top, "admin_total": len(admins), "target_name": args.target_name,
        "inputs": inputs, "parse_stats": parse_stats,
        "command": " ".join(sys.argv),
        "platform": f"Python {platform.python_version()} on {platform.system()} {platform.release()}",
        "include_computers": args.include_computers,
        "company_terms": [c for c in args.company_name if c],
        "weak_patterns": list(DEFAULT_WEAK_PATTERNS) + company_patterns,
    }
    results["meta"] = {
        "tool": "NullPAT", "version": VERSION,
        "author": f"{AUTHOR_NAME} ({AUTHOR_HANDLE})",
        "links": {"linkedin": AUTHOR_LINKEDIN, "github": AUTHOR_GITHUB, "youtube": AUTHOR_YOUTUBE},
        "target_name": args.target_name,
        "risk_rating": risk_rating(results),
        "findings": build_findings(results, meta),
        "inputs": inputs, "parse_stats": parse_stats,
    }

    os.makedirs(args.output_dir, exist_ok=True)
    title = f'NullPAT Report{" - " + args.target_name if args.target_name else ""}'

    formats = ["html", "csv", "json", "txt"] if args.format == "all" else [args.format]
    written = []
    for fmt in formats:
        if fmt == "html":
            out_path = os.path.join(args.output_dir, "nullpat_report.html")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(render_html(results, meta, title))
            written.append(out_path)
        elif fmt == "json":
            out_path = os.path.join(args.output_dir, "nullpat_report.json")
            write_json(results, out_path)
            written.append(out_path)
        elif fmt == "csv":
            written.extend(write_csv(results, args.output_dir))
        elif fmt == "txt":
            out_path = os.path.join(args.output_dir, "nullpat_report.txt")
            write_txt(results, out_path)
            written.append(out_path)

    print_summary(results, pal)
    elapsed = time.time() - t0
    status.ok(f"Report written in {elapsed:.2f}s:")
    for p in written:
        print("    " + pal.info(p))
    print()
    print("  " + pal.dim(f"Built by {AUTHOR_NAME} ({AUTHOR_HANDLE}) \u00b7 {AUTHOR_LINKEDIN}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
