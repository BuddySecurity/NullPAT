# NullPAT

> **Built by Ahmed Hasan (@BudSec)** &nbsp;·&nbsp;
> [LinkedIn](https://www.linkedin.com/in/budsec) &nbsp;·&nbsp;
> [GitHub](https://github.com/BuddySecurity) &nbsp;·&nbsp;
> [YouTube](https://youtube.com/@BudSec)

**NullPAT** (the **Null**-session **P**assword **A**udit **T**ool) is a from-scratch,
dependency-free reimplementation of [DPAT](https://github.com/clr2of8/DPAT) for turning a
cracked-password list and an NTDS dump into an audit-ready report.

NullPAT doesn't crack anything. It correlates passwords you've already recovered (via
Hashcat, John, or any other cracking rig, in an authorized engagement) against a domain's
NTDS dump, and reports the things an auditor or client actually needs to know: crack rate,
password reuse, blank passwords, legacy LM hashes, privileged-account exposure, and
password-hygiene trends.

## What's different from DPAT

| | DPAT | NullPAT |
|---|---|---|
| Runtime | requires Ruby | Python 3, **zero third-party dependencies** |
| Output | one static HTML file | HTML (default), CSV, JSON, or TXT — pick with `-f/--format` |
| Report | plain tables | dashboard-style report: summary cards, inline SVG charts, searchable/filterable tables, collapsible reuse groups, masked passwords with a reveal toggle |
| CLI | minimal | colorful banner, live progress bars, a color-coded terminal summary with an overall risk rating |
| Extras | — | `$HEX[...]` password decoding, password-history reuse tracking, configurable weak-pattern and company-name matching, privileged-account cross-referencing |

## What's new in v1.1.0

- **`--example-commands`** prints ready-to-copy example commands for every flag and workflow
  (quick start, admins, disabled, history, company terms, policy length, every output
  format, CI/quiet mode, preparing inputs, a full engagement example) and exits.
  `-h` is now grouped by purpose and points to it.
- **Dashboard-style HTML report.** Opens on a dashboard (risk rating + meter, account-status
  donut, findings by severity, and labelled KPI cards for scope, risk indicators and password
  statistics). A sticky sidebar links to every section with live highlighting; every section is
  collapsible, with **Expand all / Collapse all**; every KPI card is a link that opens and
  scrolls to the evidence behind the number; each section has prev / next / back-to-dashboard
  links; tables are sortable and filterable.
- **Findings & Risk Register** with stable IDs (`NP-01` ...), severity, count, % of base,
  recommendation and an *Evidence* link, plus an **Impact Assessment** section.
- **Full statistics:** per-domain crack rate, strength buckets, complexity distribution,
  composition stats (uppercase / digits / special / year patterns / policy compliance), length
  distribution with cumulative %, top passwords with counts and %, reuse blast radius,
  privileged (cracked / blank / not found), disabled-account exposure, weak patterns by rule.
- **Audit Trail & Methodology** section: command line, tool version, input file SHA-256 hashes,
  line counts, parsing statistics, risk-rating rules and the weak-pattern rules applied.
- Author credit and links in the CLI banner, `--help`, `--version`, HTML, TXT, CSV and JSON.

## Quick start

```bash
python3 nullpat.py --ntds ntds.dit.txt --cracked hashcat.potfile
```

This writes `nullpat_report.html` to `./nullpat_report/` by default and prints a
color-coded summary to the terminal.

### Fuller example

```bash
python3 nullpat.py \
  --ntds ntds.dit.txt \
  --cracked hashcat.potfile \
  --history ntds_history.txt \
  --admins domain_admins.txt \
  --company-name Contoso \
  --min-length 12 \
  --target-name "Contoso Corp - Q4 Domain Password Audit" \
  --output-dir ./contoso_report \
  --format all
```

## Inputs

- `--ntds` *(required)* — an NTDS dump in `secretsdump.py` line format:
  `DOMAIN\username:RID:LMHASH:NTHASH:::`. Computer accounts (`$`) are excluded by default
  (`--include-computers` to keep them).
- `--cracked` *(required)* — a `hash:password` cracked list, as produced by a Hashcat
  potfile (`hashcat --show --potfile-path ... ntlm_hashes.txt > cracked.txt`) or similar.
  Hashcat's `$HEX[...]` password escaping is decoded automatically.
- `--history` *(optional)* — an NTDS dump that also includes `*_historyN` accounts
  (`secretsdump.py -history`), used to flag accounts that keep recycling the same small
  set of passwords.
- `--admins` *(optional)* — a text file of privileged usernames, one per line, used to
  flag cracked privileged accounts.
- `--disabled` *(optional)* — a text file of disabled usernames, flagged (not excluded)
  in the cracked-accounts table.
- `--company-name` *(optional, repeatable)* — extra terms to flag as weak patterns (e.g.
  the client's name, product names, a "SeasonYear" pattern you've seen in a prior
  engagement).

## Output

- `--format html` *(default)* — a single self-contained `nullpat_report.html` with 14
  navigable, collapsible sections: Dashboard, Findings & Risk Register, Impact Assessment,
  Account Status & Cracked Accounts, Strength & Composition, Length Distribution, Top
  Passwords, Privileged Accounts, Password Reuse, Username = Password, Weak Patterns,
  Password History, Blank & LM, and Audit Trail. Passwords are blurred by default with a
  one-click reveal toggle, since the report is meant to be safe to pull up during a readout
  meeting. Print / PDF expands every section automatically.
- `--format csv` — `summary.csv`, `cracked_accounts.csv`, `password_reuse.csv`,
  `weak_pattern_hits.csv`, `username_eq_password.csv`.
- `--format json` — one `nullpat_report.json` with every computed metric, for feeding
  into other tooling.
- `--format txt` — a plain-text version of the summary, for pasting into a ticket or
  terminal-only environments.
- `--format all` — writes every format above.

## Handling the output responsibly

This report contains cleartext passwords recovered during an authorized engagement.
Treat every generated report as client-confidential data:

- Store it encrypted / in an access-controlled location.
- Don't leave `--format all` CSV/JSON output lying around unencrypted — only the HTML
  report blurs passwords by default.
- Delete the report once remediation reporting is complete, per your engagement's data
  handling policy.

## Files in this package

```
nullpat.py              the tool (single file, Python 3 standard library only)
README.md               this file
sample_data/             synthetic NTDS + cracked-password fixtures for a test run
```

Try it against the bundled sample data:

```bash
python3 nullpat.py \
  --ntds sample_data/ntds_history_sample.txt \
  --cracked sample_data/cracked_sample.txt \
  --admins sample_data/admins_sample.txt \
  --history sample_data/ntds_history_sample.txt \
  --target-name "Demo Corp" \
  --format all
```

All usernames, passwords, and hashes in `sample_data/` are synthetic fixtures generated
for testing — not real credentials.

## Author

**Ahmed Hasan (@BudSec)**

- LinkedIn: https://www.linkedin.com/in/budsec
- GitHub: https://github.com/BuddySecurity
- YouTube: https://youtube.com/@BudSec
