"""CLI entry point for CorpCrack."""

from __future__ import annotations

import argparse
import sys
import tomllib
from datetime import date
from pathlib import Path

from corpcrack import __version__
from corpcrack.generator import DEFAULT_WEIGHTS, MONTH_TO_SEASONS, generate

BANNER = r"""
   ______                 ______                __
  / ____/___  _________  / ____/________ ______/ /__
 / /   / __ \/ ___/ __ \/ /   / ___/ __ `/ ___/ //_/
/ /___/ /_/ / /  / /_/ / /___/ /  / /_/ / /__/ ,<
\____/\____/_/  / .___/\____/_/   \__,_/\___/_/|_|
               /_/
"""

DEFAULT_CONFIG_TEMPLATE = """\
# CorpCrack Configuration
#
# Each pattern has exactly one weight.  Lower = higher priority.
# Changing one key never affects any other pattern's position.
# Only override the keys you want to change.

[weights]
# Hand-ranked static passwords (Welcome1, Password123!, keyboard walks, etc.)
static = 100

# Current season + current year, auto-detected (Spring2026!, April2026!)
season_current = 200

# Current month + current year, auto-detected (April2026!, Apr26!)
month_current = 250

# Welcome/Password + current year (Welcome2026!, Password2026!)
welcome_current = 275

# Well-known phrases (Winteriscoming2025!)
special = 300

# Company name + basic suffix or year (CompanyName1!, CompanyName2025!)
company = 400

# Company name + current season/month (CompanyNameSpring2026!)
company_current = 450

# Welcome/Password + any year (Welcome2024!, Password2025!)
welcome = 500

# Welcome2 + company + year (Welcome2CompanyName2025!)
welcome_company = 550

# Company name + year (CompanyName2024!, CompanyName@2025)
company_year = 600

# Season + any year (Summer2024!, Winter2023!)
season = 700

# Company name + season + year (CompanyNameSummer2024!)
company_season = 800

# Month + any year (January2024!, Oct25!)
month = 900

# Company name + month + year (CompanyNameJan2024!)
company_month = 1000

# Leetspeak penalties — added to the base weight of each password.
# A common leet variant of a static password gets: static + leet_common = 100 + 10000
leet_common = 10000
leet_multi = 20000
leet_uncommon = 30000
"""


def _info(msg: str) -> None:
    """Print informational message to stderr (keeps stdout clean for piping)."""
    print(msg, file=sys.stderr)


def _load_weights(config_path: str) -> dict[str, int]:
    """Load tier weights from a TOML config file, merged over defaults."""
    path = Path(config_path)
    try:
        with path.open("rb") as f:
            config = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        print(f"corpcrack: error: invalid TOML in {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    weights = dict(DEFAULT_WEIGHTS)
    if "weights" not in config:
        return weights

    for key, value in config["weights"].items():
        if not isinstance(value, int):
            print(
                f"corpcrack: error: weight '{key}' must be an integer, got {type(value).__name__}",
                file=sys.stderr,
            )
            sys.exit(1)
        weights[key] = value

    return weights


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corpcrack",
        description="Corporate password list generator for internal security assessments.",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    company = parser.add_argument_group("company name")
    company.add_argument(
        "-s", "--company-short",
        metavar="NAME",
        help="Short / abbreviated company name",
    )
    company.add_argument(
        "-l", "--company-long",
        metavar="NAME",
        help="Full company name",
    )

    years = parser.add_argument_group("year range")
    years.add_argument(
        "--year-start",
        type=int,
        metavar="YEAR",
        help="Start year for time-based passwords (inclusive)",
    )
    years.add_argument(
        "--year-end",
        type=int,
        metavar="YEAR",
        help="End year for time-based passwords (inclusive)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write passwords to FILE instead of stdout",
    )
    output.add_argument(
        "--top",
        type=int,
        metavar="N",
        help="Output only the top N most likely passwords",
    )
    output.add_argument(
        "--min-length",
        type=int,
        default=0,
        metavar="N",
        help="Exclude passwords shorter than N characters",
    )
    output.add_argument(
        "--max-length",
        type=int,
        default=0,
        metavar="N",
        help="Exclude passwords longer than N characters",
    )
    output.add_argument(
        "--exclude",
        metavar="FILE",
        help="Exclude passwords found in FILE (one per line)",
    )

    config = parser.add_argument_group("config")
    config.add_argument(
        "--config",
        metavar="FILE",
        help="Load tier weights from a TOML config file",
    )
    config.add_argument(
        "--init-config",
        nargs="?",
        const="corpcrack.toml",
        metavar="PATH",
        help="Generate a starter config file (corpcrack.toml)",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()

    # Show help if no arguments given
    if argv is None and len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(0)

    args = parser.parse_args(argv)

    # Handle --init-config early (write file and exit)
    if args.init_config is not None:
        out = Path(args.init_config)
        if out.exists():
            print(f"corpcrack: error: {out} already exists", file=sys.stderr)
            sys.exit(1)
        out.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        print(f"Config written to {out.resolve()}", file=sys.stderr)
        return

    # Validate inputs
    if (args.year_start is None) != (args.year_end is None):
        parser.error("--year-start and --year-end must be used together")
    if args.year_start is not None and args.year_start > args.year_end:
        parser.error("--year-start must be <= --year-end")
    if args.top is not None and args.top < 1:
        parser.error("--top must be a positive integer")
    if args.exclude and not Path(args.exclude).is_file():
        parser.error(f"exclude file not found: {args.exclude}")
    if args.config and not Path(args.config).is_file():
        parser.error(f"config file not found: {args.config}")

    # Load weights
    weights = _load_weights(args.config) if args.config else None

    _info(BANNER)
    _info(f"  v{__version__} | Corporate Password List Generator")
    _info("")

    # Summarise configuration
    if args.config:
        _info(f"  [+] Config file        : {args.config}")
    if args.company_short:
        _info(f"  [+] Company short name : {args.company_short}")
    if args.company_long:
        _info(f"  [+] Company long name  : {args.company_long}")
    if args.year_start is not None:
        _info(f"  [+] Year range         : {args.year_start} - {args.year_end}")

        # Show current-time boost status
        today = date.today()
        if args.year_start <= today.year <= args.year_end:
            season = MONTH_TO_SEASONS[today.month][0]
            _info(f"  [+] Current time boost : {season} {today.year} (auto-detected)")

    if args.min_length > 0:
        _info(f"  [+] Min length filter  : {args.min_length}")
    if args.max_length > 0:
        _info(f"  [+] Max length filter  : {args.max_length}")
    if args.top is not None:
        _info(f"  [+] Top N limit        : {args.top}")
    if args.exclude:
        _info(f"  [+] Exclude file       : {args.exclude}")
    _info("")

    # Generate
    passwords = generate(
        company_short=args.company_short,
        company_long=args.company_long,
        year_start=args.year_start,
        year_end=args.year_end,
        weights=weights,
    )

    total_generated = len(passwords)

    # Apply filters (order matters: exclude → length → top)
    if args.exclude:
        exclude_path = Path(args.exclude)
        excluded = {
            line.strip()
            for line in exclude_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        }
        passwords = [p for p in passwords if p not in excluded]

    if args.min_length > 0:
        passwords = [p for p in passwords if len(p) >= args.min_length]
    if args.max_length > 0:
        passwords = [p for p in passwords if len(p) <= args.max_length]
    if args.top is not None:
        passwords = passwords[:args.top]

    _info(f"  [*] Generated {total_generated} total, outputting {len(passwords)} passwords")

    # Output
    if args.output:
        out_path = Path(args.output)
        out_path.write_text("\n".join(passwords) + "\n", encoding="utf-8")
        _info(f"  [*] Written to {out_path.resolve()}")
    else:
        sys.stdout.write("\n".join(passwords) + "\n")

    _info("")
    _info("  [*] Done.")
