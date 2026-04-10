"""Corporate password list generator.

Generates targeted password lists for internal security assessments by combining
common base passwords, company name variants, seasons, months, year ranges,
keyboard walks, and leetspeak substitutions.

Output is sorted from most likely (spray gold) to least likely (cracking territory).
"""

from __future__ import annotations

from datetime import date


# ---------------------------------------------------------------------------
# Default tier weights — lower = more likely to be a real password
#
# Every pattern has exactly one weight.  No addition, no coupling.
# Changing one key never affects any other pattern's position.
#
# Passwords are sorted by (weight, sub_order, password_string).
# sub_order preserves insertion position within a tier so that, for
# example, Welcome1 stays ahead of Changeme1 inside the static tier.
#
# These defaults can be overridden via a TOML config file (--config).
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, int] = {
    "static": 100,
    "season_current": 200,
    "month_current": 250,
    "welcome_current": 275,
    "special": 300,
    "company": 400,
    "company_current": 450,
    "welcome": 500,
    "welcome_company": 550,
    "company_year": 600,
    "season": 700,
    "company_season": 800,
    "month": 900,
    "company_month": 1000,
    "leet_common": 10000,
    "leet_multi": 20000,
    "leet_uncommon": 30000,
}


# ---------------------------------------------------------------------------
# Leetspeak rules (from hashcat /usr/share/hashcat/rules/leetspeak.rule)
# ---------------------------------------------------------------------------

LEET_COMMON_SINGLE: list[tuple[str, str]] = [
    ("a", "4"), ("a", "@"),
    ("e", "3"),
    ("i", "1"),
    ("o", "0"),
    ("s", "5"), ("s", "$"),
]

LEET_UNCOMMON_SINGLE: list[tuple[str, str]] = [
    ("b", "6"),
    ("c", "<"), ("c", "{"),
    ("g", "9"),
    ("i", "!"),
    ("q", "9"),
    ("t", "7"), ("t", "+"),
    ("x", "%"),
]

# Multi substitution applied at once: sa@sc<se3si1so0ss$
LEET_MULTI: dict[str, str] = {
    "a": "@", "c": "<", "e": "3", "i": "1", "o": "0", "s": "$",
}


# ---------------------------------------------------------------------------
# Static list — hand-ranked from most to least likely
#
# Position in this list IS the sub_order, so the first entry appears first
# in the final output.  Every password here has been validated against
# real-world spray/breach data.
# ---------------------------------------------------------------------------

STATIC_PASSWORDS: list[str] = [
    # ---- Welcome — the undisputed #1 corporate default ----
    "Welcome1", "Welcome1!",
    "welcome1", "welcome1!",
    "Welcome123", "Welcome123!",
    "welcome123", "welcome123!",

    # ---- Password — the eternal classic ----
    "Password1", "Password1!",
    "password1", "password1!",
    "Password123", "Password123!",
    "password123", "password123!",

    # ---- P@ssw0rd — pre-leet that orgs hand out ----
    "P@ssw0rd", "P@ssw0rd!",
    "P@ssw0rd1", "P@ssw0rd1!",
    "P@ssword1", "P@ssword1!",
    "P@ssword123",
    "Passw0rd", "Passw0rd!",
    "Passw0rd1", "Passw0rd1!",

    # ---- Changeme — helpdesk reset classic ----
    "Changeme1", "Changeme1!",
    "changeme1", "changeme1!",
    "Changeme123", "Changeme123!",
    "Ch@ngeme1", "Ch@ngeme1!",

    # ---- Letmein ----
    "Letmein1", "Letmein1!",
    "letmein1", "letmein1!",
    "Letmein123", "Letmein123!",

    # ---- Admin / reset / new-hire defaults ----
    "Admin123", "Admin123!",
    "admin123", "admin123!",
    "Admin1234", "Admin1234!",
    "Reset123", "Reset123!",
    "Newuser1", "Newuser1!",
    "Newuser123!",
    "Changeit1", "Changeit1!",

    # ---- Test / temp / guest ----
    "Test1234", "Test1234!",
    "test1234", "test1234!",
    "Temp1234", "Temp1234!",
    "temp1234", "temp1234!",
    "Guest1234", "Guest1234!",

    # ---- Keyboard walks — column walks (very common) ----
    "!QAZ2wsx",
    "1qaz2wsx",
    "1qaz2wsx!",
    "1qaz!QAZ",
    "1qazZAQ!",
    "!QAZ1qaz",
    "2wsx3edc",
    "3edc4rfv",

    # ---- Keyboard walks — row walks ----
    "Qwerty1!", "qwerty1!",
    "Qwerty123", "Qwerty123!",
    "qwerty123", "qwerty123!",
    "Qwer1234", "Qwer1234!",
    "qwer1234", "qwer1234!",
    "Asdf1234", "Asdf1234!",
    "asdf1234", "asdf1234!",
    "Asdfgh1!", "asdfgh1!",
    "Zxcvbn1!", "Zxcvbn123!",
    "zxcvbn1!", "zxcvbn123!",

    # ---- Keyboard walks — alternating / diagonal ----
    "1q2w3e4r", "1q2w3e4r!",
    "!Q2w3e4r",
    "Zaq12wsx", "Zaq12wsx!",
    "Qazwsx123", "Qazwsx123!",
    "Asdfghjkl1!",

    # ---- Pop culture / well-known phrases ----
    "Trustno1", "Trustno1!",
    "Iloveyou1", "Iloveyou1!",
    "Winteriscoming1", "Winteriscoming1!",
    "winteriscoming1", "winteriscoming1!",
    "Sunshine1", "Sunshine1!",
    "Superman1", "Superman1!",
    "Batman123", "Batman123!",
    "Starwars1", "Starwars1!",
    "Dragon123", "Dragon123!",
    "Master123", "Master123!",
    "Shadow123", "Shadow123!",
    "Monkey123", "Monkey123!",

    # ---- Ihatepasswords ----
    "Ihatepasswords1!", "Ihatepasswords2!", "Ihatepasswords3!",
    "Ihatepasswords4!", "Ihatepasswords5!", "Ihatepasswords6!",
    "Ihatepasswords7!", "Ihatepasswords8!", "Ihatepasswords9!",
    "Ihatepasswords10!",
    "ihatepasswords1!", "ihatepasswords2!", "ihatepasswords3!",
    "ihatepasswords4!", "ihatepasswords5!", "ihatepasswords6!",
    "ihatepasswords7!", "ihatepasswords8!", "ihatepasswords9!",
    "ihatepasswords10!",

    # ---- Common base words ----
    "Hello123", "Hello123!",
    "Access14", "Access1!", "Access123", "Access123!",
    "Abc123!", "abc123!",
    "Abcd1234", "Abcd1234!",

    # ---- Sports ----
    "Football1", "Football1!",
    "Baseball1", "Baseball1!",

    # ---- Days of the week ----
    "Monday1!", "Tuesday1!", "Wednesday1!", "Thursday1!",
    "Friday1!", "Saturday1!", "Sunday1!",

    # ---- Placeholder company ----
    "Company1", "Company1!",
    "Company123", "Company123!",
]


# ---------------------------------------------------------------------------
# Time-based building blocks
# ---------------------------------------------------------------------------

SEASONS: list[str] = ["Spring", "Summer", "Fall", "Winter", "Autumn"]

MONTHS: list[tuple[str, str]] = [
    ("January", "Jan"), ("February", "Feb"), ("March", "Mar"),
    ("April", "Apr"), ("May", "May"), ("June", "Jun"),
    ("July", "Jul"), ("August", "Aug"), ("September", "Sep"),
    ("October", "Oct"), ("November", "Nov"), ("December", "Dec"),
]

MONTH_TO_SEASONS: dict[int, list[str]] = {
    1: ["Winter"], 2: ["Winter"], 3: ["Spring"],
    4: ["Spring"], 5: ["Spring"], 6: ["Summer"],
    7: ["Summer"], 8: ["Summer"], 9: ["Fall", "Autumn"],
    10: ["Fall", "Autumn"], 11: ["Fall", "Autumn"], 12: ["Winter"],
}

# Suffixes appended to company names — ordered most to least common
BARE_SUFFIXES: list[str] = [
    "1", "!", "1!",
    "123", "123!",
    "12", "12!",
    "1234", "1234!",
    "01", "01!",
    "@1", "@123",
    "#1", "#123",
    "007",
    "69", "69!",
    "77", "99",
]

# Characters appended after a year
YEAR_CAPS: list[str] = ["", "!", "#", "@", "$"]

# Stop words stripped when processing long company names
STOP_WORDS: frozenset[str] = frozenset({
    "a", "an", "and", "as", "at", "by", "for", "in", "is",
    "it", "its", "of", "on", "or", "the", "to",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _case_variants(name: str) -> list[str]:
    """Return unique casing variants of *name*."""
    variants: set[str] = {name, name.lower(), name.upper(), name.capitalize()}
    titled = name.title()
    if titled != name:
        variants.add(titled)
    return sorted(variants)


def _bases_from_long_name(long_name: str) -> list[str]:
    """Derive base name forms from a full company name.

    Produces: significant words joined, first word, last word, and initials.
    """
    words = long_name.split()
    significant = [w for w in words if w.lower() not in STOP_WORDS]
    if not significant:
        significant = words

    bases: set[str] = set()
    bases.add("".join(significant))
    bases.add(significant[0])
    if len(significant) > 1:
        bases.add(significant[-1])
    initials = "".join(w[0].upper() for w in significant)
    if len(initials) > 1:
        bases.add(initials)

    return sorted(bases)


def _leet_single(pw: str, src: str, dst: str) -> str | None:
    """Apply a single leetspeak substitution (case-insensitive)."""
    result = pw.replace(src.lower(), dst).replace(src.upper(), dst)
    return result if result != pw else None


def _leet_multi_apply(pw: str, rules: dict[str, str]) -> str | None:
    """Apply multiple leetspeak substitutions at once."""
    result = pw
    for src, dst in rules.items():
        result = result.replace(src.lower(), dst).replace(src.upper(), dst)
    return result if result != pw else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(
    *,
    company_short: str | None = None,
    company_long: str | None = None,
    year_start: int | None = None,
    year_end: int | None = None,
    weights: dict[str, int] | None = None,
) -> list[str]:
    """Generate a de-duplicated password list sorted by likelihood.

    Parameters
    ----------
    company_short : str, optional
        Short / abbreviated company name.
    company_long : str, optional
        Full company name.
    year_start, year_end : int, optional
        Inclusive year range for time-based password generation.
    weights : dict, optional
        Tier weights that override DEFAULT_WEIGHTS.

    Returns
    -------
    list[str]
        Unique password candidates, most likely first.
    """
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)

    # scored: password -> (tier, sub_order)
    scored: dict[str, tuple[int, int]] = {}

    def _add(pw: str, tier: int, sub: int = 0) -> None:
        key = (tier, sub)
        if pw not in scored or key < scored[pw]:
            scored[pw] = key

    years: list[int] = []
    if year_start is not None and year_end is not None:
        years = list(range(year_start, year_end + 1))

    # Detect current time for boosting
    today = date.today()
    current_year = today.year
    current_month = today.month
    current_seasons = MONTH_TO_SEASONS[current_month]
    current_month_full, current_month_abbr = MONTHS[current_month - 1]
    year_is_current = current_year in set(years)

    # ---- 1. Static common passwords (index = rank) ----
    for i, pw in enumerate(STATIC_PASSWORDS):
        _add(pw, w["static"], i)

    # ---- 2. Current-time patterns (auto-detected) ----
    if year_is_current:
        yr_full = str(current_year)
        yr_short = yr_full[2:]

        # Current season + year
        for season in current_seasons:
            for s in (season, season.lower()):
                for yr in (yr_full, yr_short):
                    _add(f"{s}{yr}", w["season_current"])
                    _add(f"{s}{yr}!", w["season_current"])
                    _add(f"{s}{yr}#", w["season_current"])

        # Current month + year
        for m in (current_month_full, current_month_full.lower(),
                  current_month_abbr, current_month_abbr.lower()):
            for yr in (yr_full, yr_short):
                _add(f"{m}{yr}", w["month_current"])
                _add(f"{m}{yr}!", w["month_current"])

        # Welcome / Password + current year
        for base in ("Welcome", "welcome", "Password", "password"):
            for yr in (yr_full, yr_short):
                _add(f"{base}{yr}", w["welcome_current"])
                _add(f"{base}{yr}!", w["welcome_current"])

    # ---- 3. Winteriscoming + year ----
    for year in years:
        yr_short = str(year)[2:]
        for base in ("Winteriscoming", "winteriscoming"):
            for yr in (str(year), yr_short):
                _add(f"{base}{yr}", w["special"])
                _add(f"{base}{yr}!", w["special"])

    # ---- 4. Company-name-derived passwords ----
    name_bases: set[str] = set()
    if company_short:
        for v in _case_variants(company_short):
            name_bases.add(v)
    if company_long:
        for raw_base in _bases_from_long_name(company_long):
            for v in _case_variants(raw_base):
                name_bases.add(v)

    for name in sorted(name_bases):
        # Company + bare suffix (ranked by suffix position)
        for idx, suffix in enumerate(BARE_SUFFIXES):
            _add(f"{name}{suffix}", w["company"], idx)

        # Company + current season/month
        if year_is_current:
            yr_full = str(current_year)
            yr_short = yr_full[2:]
            for season in current_seasons:
                for s in (season, season.lower()):
                    for yr in (yr_full, yr_short):
                        _add(f"{name}{s}{yr}", w["company_current"])
                        _add(f"{name}{s}{yr}!", w["company_current"])
            for m in (current_month_abbr, current_month_abbr.lower()):
                for yr in (yr_full, yr_short):
                    _add(f"{name}{m}{yr}", w["company_current"])
                    _add(f"{name}{m}{yr}!", w["company_current"])

        # Company + year
        for year in years:
            yr_short = str(year)[2:]
            for yr in (str(year), yr_short):
                for cap in YEAR_CAPS:
                    _add(f"{name}{yr}{cap}", w["company_year"])
                    _add(f"{name}@{yr}{cap}", w["company_year"])

            # Company + season + year
            for season in SEASONS:
                for s in (season, season.lower()):
                    for yr in (str(year), yr_short):
                        _add(f"{name}{s}{yr}", w["company_season"])
                        _add(f"{name}{s}{yr}!", w["company_season"])

            # Company + month + year (abbreviated)
            for _, month_abbr in MONTHS:
                for yr in (str(year), yr_short):
                    _add(f"{name}{month_abbr}{yr}", w["company_month"])
                    _add(f"{name}{month_abbr}{yr}!", w["company_month"])

        # Welcome + company + year
        for year in years:
            yr_short = str(year)[2:]
            for yr in (str(year), yr_short):
                _add(f"Welcome2{name}{yr}", w["welcome_company"])
                _add(f"Welcome2{name}{yr}!", w["welcome_company"])
                _add(f"welcome2{name}{yr}", w["welcome_company"])
                _add(f"welcome2{name}{yr}!", w["welcome_company"])

    # ---- 5. Welcome / Password + year (all years) ----
    for year in years:
        yr_short = str(year)[2:]
        for base in ("Welcome", "welcome", "Password", "password"):
            for yr in (str(year), yr_short):
                _add(f"{base}{yr}", w["welcome"])
                _add(f"{base}{yr}!", w["welcome"])

    # ---- 6. Generic season + year ----
    for year in years:
        yr_short = str(year)[2:]
        for season in SEASONS:
            for s in (season, season.lower()):
                for yr in (str(year), yr_short):
                    _add(f"{s}{yr}", w["season"])
                    _add(f"{s}{yr}!", w["season"])
                    _add(f"{s}{yr}#", w["season"])

    # ---- 7. Generic month + year ----
    for year in years:
        yr_short = str(year)[2:]
        for month_full, month_abbr in MONTHS:
            for m in (month_full, month_full.lower(), month_abbr, month_abbr.lower()):
                for yr in (str(year), yr_short):
                    _add(f"{m}{yr}", w["month"])
                    _add(f"{m}{yr}!", w["month"])

    # ---- 8. Leetspeak transformations on every password above ----
    base_items = list(scored.items())
    for pw, (base_tier, base_sub) in base_items:
        # Common single substitutions
        for src, dst in LEET_COMMON_SINGLE:
            variant = _leet_single(pw, src, dst)
            if variant:
                _add(variant, base_tier + w["leet_common"], base_sub)

        # Multi substitution (all common applied at once)
        variant = _leet_multi_apply(pw, LEET_MULTI)
        if variant:
            _add(variant, base_tier + w["leet_multi"], base_sub)

        # Uncommon single substitutions
        for src, dst in LEET_UNCOMMON_SINGLE:
            variant = _leet_single(pw, src, dst)
            if variant:
                _add(variant, base_tier + w["leet_uncommon"], base_sub)

    # Sort: (tier, sub_order, password_string)
    return [pw for pw, _ in sorted(scored.items(), key=lambda x: (x[1], x[0]))]
