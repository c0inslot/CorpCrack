# CorpCrack

**CorpCrack** is a targeted password list generator built for internal network assessments that produces organization-based, likelihood-sorted output.

---

## Why not just use a wordlist?

Generic wordlists (rockyou, SecLists, etc.) have no awareness of the organization you are targeting. They will never contain the patterns that employees actually set.

CorpCrack generates a single likelihood-sorted list that serves two purposes. Towards the top of the list are the most commonly identified passwords, ideal for **spraying** within a lockout window. Further down, it transitions into company-specific and leetspeak patterns better suited for **cracking**, the kind of candidates that generic wordlists will never have.

---

## Features

| Flag | Description |
|------|-------------|
| `-s NAME` | Short / abbreviated company name |
| `-l NAME` | Full company name |
| `--year-start YEAR` | Start year for time-based passwords (inclusive) |
| `--year-end YEAR` | End year for time-based passwords (inclusive) |
| `-o FILE` | Write passwords to file instead of stdout |
| `--top N` | Output only the top N most likely passwords |
| `--min-length N` | Exclude passwords shorter than N characters |
| `--max-length N` | Exclude passwords longer than N characters |
| `--exclude FILE` | Exclude passwords found in FILE (one per line) |
| `--patterns LIST` | Only include passwords from these patterns (comma-separated) |
| `--shift-modifiers MODE` | Trailing characters to append (default: `!`, `common`, `all`, `none`, or custom) |
| `--show-weights` | Print the current weight table and exit |
| `--config FILE` | Load tier weights from a TOML config file |
| `--init-config [PATH]` | Generate a starter config file (`corpcrack.toml`) |

---

## Installation

```bash
pipx install git+https://github.com/c0inslot/corpcrack
```
```
uv tool install git+https://github.com/c0inslot/corpcrack
```

---

## Usage Examples

```bash
# Full engagement run, company context, year range, write to file
corpcrack -s ACME -l "Acme Corporation" --year-start 2022 --year-end 2026 -o passwords.txt

# Quick spray list, just the top 20 most likely passwords, no company context
corpcrack --top 20

# Target enforces a 10-character minimum password policy
corpcrack -s ACME --year-start 2024 --year-end 2026 --min-length 10

# Exclude passwords you already tried in a previous spray window
corpcrack -s ACME --year-start 2024 --year-end 2026 --exclude already_tried.txt

# Only output static and company patterns
corpcrack -s ACME --year-start 2024 --year-end 2026 --patterns static,company

# Generate with all common shift modifiers (!@#$%) instead of just !
corpcrack -s ACME --year-start 2024 --year-end 2026 --shift-modifiers common

# See how your weights are currently ordered
corpcrack --show-weights
corpcrack --show-weights --config corpcrack.toml

# Generate a default config, tweak weights, then use it
corpcrack --init-config
corpcrack -s ACME --year-start 2024 --year-end 2026 --config corpcrack.toml
```

---

## How the output is sorted

Each pattern has a weight that controls where it appears in the list. Lower numbers appear first.

| Pattern | Default | Examples |
|---------|---------|----------|
| `static` | 100 | `Welcome1`, `Password123!`, keyboard walks |
| `season_current` | 200 | `Spring2026!` |
| `month_current` | 250 | `April2026!` |
| `welcome_current` | 275 | `Welcome2026!` |
| `special` | 300 | `Winteriscoming2025!` |
| `company` | 400 | `ACME1!`, `ACME123!` |
| `company_current` | 450 | `ACMESpring2026!` |
| `welcome` | 500 | `Welcome2024!`, `Password2025!` |
| `welcome_company` | 550 | `Welcome2ACME2025!` |
| `company_year` | 600 | `ACME2024!`, `ACME@2025` |
| `season` | 700 | `Summer2024!`, `Winter2023!` |
| `company_season` | 800 | `ACMESummer2024!` |
| `month` | 900 | `January2024!`, `Oct25!` |
| `company_month` | 1000 | `ACMEJan2024!` |
| `leet_common` | 10000 | `W3lcom31` |
| `leet_multi` | 20000 | `W3l<0m31` |
| `leet_uncommon` | 30000 | `Wel{ome1` |

Patterns named `*_current` match the current season or month based on your system clock. Leet variants always appear below all non-leet passwords, following the same pattern ordering as their base passwords.

---

## Custom weights

Generate a starter config:

```bash
corpcrack --init-config
```

This writes `corpcrack.toml` to the current directory. Edit the weights, then pass it in:

```bash
corpcrack -s ACME --year-start 2024 --year-end 2026 --config corpcrack.toml
```

Only the keys you include are overridden, everything else keeps its default.

**Move a specific pattern higher in the list:**

```toml
[weights]
company_season = 450
```

**Disable the current-time boost.** By default, passwords matching the current season/month rank higher. To treat them the same as any other season/month:

```toml
[weights]
season_current = 700
month_current = 900
welcome_current = 500
company_current = 800
```

**Keep leetspeak variants out of spray range.** Push them to the bottom of the list:

```toml
[weights]
leet_common = 999999
leet_multi = 999999
leet_uncommon = 999999
```