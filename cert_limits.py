#!/usr/bin/env python3
"""cert_limits.py — Let's Encrypt cert-limit tracker (house diagnostics).

For each registered domain in the config file, read Certificate
Transparency via crt.sh and report the Let's Encrypt budget position:

  * LE issuances observed in the trailing 168 hours vs the cap of 50
    per registered domain (eTLD+1) per rolling week. Every subdomain
    draws on the registered domain's single budget.
  * Duplicate certificates: per exact name-set, in-window count vs
    the cap of 5 per week.
  * When the next slot frees (oldest in-window issuance + 168h).
  * Live inventory: latest cert per name-set with expiry; anything
    expiring within 21 days is flagged.

HONESTY NOTES (also printed in the report header):
  * crt.sh returns both precertificates and final certificates; this
    script dedupes by (issuer_name, serial_number) so each issuance
    is counted once.
  * crt.sh's JSON carries no log-entry timestamp, so issuance time
    is approximated by the cert's not_before (Let's Encrypt sets it
    at issuance, backdated at most ~1 hour — immaterial against a
    168-hour window).
  * CT cannot show which account issued a cert, nor whether an
    issuance was a renewal. Renewals are exempt from LE's 50/week
    cap but are counted here (inflating the count), while crt.sh
    ingestion lag can miss recent certs entirely (deflating it —
    phextura.com's 2026-11-11 cert was still absent from crt.sh's
    index four days later). Treat every number as an estimate from
    crt.sh's index, never as LE's internal counter.

Exit code is non-zero when any domain is UNVERIFIED (crt.sh query
failed after retries) or a threshold is crossed: >=80% of the 50-cap,
any name-set at >=4 duplicates, or any live cert <14 days to expiry
(expired counts). That makes the script safe to gate a Jenkins job.

Usage: cert_limits.py [--config domains.txt]
Stdlib only. All report times are America/Chicago.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/Chicago")
WINDOW = timedelta(hours=168)
WEEKLY_CAP = 50
NEAR_CAP = 40  # 80% of the weekly cap
DUP_CAP = 5
DUP_WARN = 4
EXPIRY_FLAG_DAYS = 21
EXPIRY_CROSS_DAYS = 14
USER_AGENT = "cert-limits-tracker/1.0 (wbic16 house diagnostics)"
QUERY_DELAY_S = 1.5
FETCH_TIMEOUT_S = 60


def parse_ts(text):
    """Parse a crt.sh timestamp (UTC, no offset) into an aware datetime."""
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1]
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fmt_short(dt):
    """'Tue 03:12' in local time."""
    return dt.astimezone(LOCAL_TZ).strftime("%a %H:%M")


def fmt_full(dt):
    """'Tue 2026-11-17 03:12 CST' in local time."""
    return dt.astimezone(LOCAL_TZ).strftime("%a %Y-%m-%d %H:%M %Z")


def name_set(entry):
    names = set()
    for raw in entry.get("name_value", "").splitlines():
        name = raw.strip().lower().rstrip(".")
        if name:
            names.add(name)
    return tuple(sorted(names))


def issuer_short(issuer_name):
    parts = {}
    for chunk in issuer_name.split(","):
        chunk = chunk.strip()
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            parts[key.strip()] = value.strip()
    org = parts.get("O", "")
    cn = parts.get("CN", "")
    label = (org + " " + cn).strip()
    return label or issuer_name


def is_lets_encrypt(issuer_name):
    return "Let's Encrypt" in issuer_name


def fetch_domain(domain):
    """Return the deduped cert list for a domain, or None if unverified.

    crt.sh is famously flaky: retry on 503/timeouts with backoff.
    A failure returns None so the caller reports UNVERIFIED — a failed
    query is never reported as zero certs.
    """
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    delays = [0, 5, 20]
    for attempt, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:
                payload = resp.read().decode("utf-8", "replace")
            entries = json.loads(payload) if payload.strip() else []
            break
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            if attempt == len(delays) - 1:
                return None
    # Dedupe precert + leaf (and multi-log duplicates) by
    # (issuer_name, serial_number); keep the earliest not_before,
    # which stands in for issuance time (see header notes).
    deduped = {}
    for entry in entries:
        key = (entry.get("issuer_name", ""), entry.get("serial_number", ""))
        if key not in deduped:
            deduped[key] = entry
        else:
            old = parse_ts(deduped[key]["not_before"])
            new = parse_ts(entry["not_before"])
            if new < old:
                deduped[key] = entry
    return list(deduped.values())


def analyse(domain, certs, now):
    window_start = now - WINDOW
    result = {"domain": domain, "crossings": []}

    le_certs = [c for c in certs if is_lets_encrypt(c.get("issuer_name", ""))]
    in_window = []
    for cert in le_certs:
        ts = parse_ts(cert["not_before"])
        if ts >= window_start:
            in_window.append((ts, cert))
    in_window.sort(key=lambda pair: pair[0])
    result["issued"] = len(in_window)

    dup_counts = Counter(name_set(cert) for _, cert in in_window)
    if dup_counts:
        worst_set, worst_n = dup_counts.most_common(1)[0]
        result["dup_max"] = worst_n
        result["dup_set"] = worst_set
    else:
        result["dup_max"] = 0
        result["dup_set"] = ()

    result["next_slot"] = None
    if in_window:
        result["next_slot"] = in_window[0][0] + WINDOW

    # Live inventory: latest-issued cert per name-set, any issuer.
    # A name-set counts as live only when that latest cert is still
    # unexpired; a name-set whose newest cert already expired is
    # history, not inventory, and must not trip the expiring flags.
    latest = {}
    for cert in certs:
        key = name_set(cert)
        ts = parse_ts(cert["not_before"])
        if key not in latest or ts > latest[key][0]:
            latest[key] = (ts, cert)
    live = {key: pair for key, pair in latest.items()
            if parse_ts(pair[1]["not_after"]) > now}
    result["live_sets"] = len(live)
    expiring = []
    for key, (_, cert) in live.items():
        not_after = parse_ts(cert["not_after"])
        days_left = (not_after - now).total_seconds() / 86400.0
        if days_left < EXPIRY_FLAG_DAYS:
            expiring.append((not_after, key, cert, days_left))
    expiring.sort(key=lambda item: item[0])
    result["expiring"] = expiring

    if result["issued"] >= NEAR_CAP:
        result["crossings"].append(
            "issuances %d/%d (>=80%% of cap)" % (result["issued"], WEEKLY_CAP))
    if result["dup_max"] >= DUP_WARN:
        result["crossings"].append(
            "duplicate name-set at %d/%d" % (result["dup_max"], DUP_CAP))
    for not_after, key, cert, days_left in expiring:
        if days_left < EXPIRY_CROSS_DAYS:
            result["crossings"].append(
                "cert for %s expires %s (<14d)"
                % (", ".join(key), fmt_full(not_after)))
    return result


def block_lines(r):
    lines = [r["domain"]]
    lines.append("  LE issuances (trailing 168h, CT-observed): %d/%d"
                 % (r["issued"], WEEKLY_CAP))
    if r["dup_set"]:
        lines.append("  duplicates: max %d/%d — {%s} x%d"
                     % (r["dup_max"], DUP_CAP, ", ".join(r["dup_set"]),
                        r["dup_max"]))
    else:
        lines.append("  duplicates: max 0/%d" % DUP_CAP)
    if r["next_slot"] is not None:
        lines.append("  next slot frees: %s" % fmt_full(r["next_slot"]))
    lines.append("  live name-sets in CT: %d" % r["live_sets"])
    if r["expiring"]:
        for not_after, key, cert, days_left in r["expiring"]:
            state = "EXPIRED" if days_left < 0 else "%.0fd left" % days_left
            lines.append("  expiring <21d: {%s} — %s (%s, %s)"
                         % (", ".join(key), fmt_full(not_after),
                            issuer_short(cert.get("issuer_name", "")), state))
    else:
        lines.append("  expiring <21d: none")
    for crossing in r["crossings"]:
        lines.append("  !! threshold: %s" % crossing)
    return lines


def summary_line(r):
    if r.get("unverified"):
        return "%s: UNVERIFIED (crt.sh query failed after retries)" % r["domain"]
    parts = ["%s: %d/%d this week" % (r["domain"], r["issued"], WEEKLY_CAP),
             "dup max %d/%d" % (r["dup_max"], DUP_CAP)]
    if r["next_slot"] is not None:
        parts.append("next slot %s" % fmt_short(r["next_slot"]))
    if r["expiring"]:
        parts.append("%d cert%s expiring <21d"
                     % (len(r["expiring"]), "s" if len(r["expiring"]) != 1 else ""))
    elif r["live_sets"]:
        parts.append("no certs expiring <21d")
    else:
        parts.append("no live certs in CT")
    return " · ".join(parts)


def load_domains(config_path):
    domains = []
    for line in Path(config_path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def main(argv):
    config = Path(__file__).with_name("domains.txt")
    args = argv[1:]
    if "--config" in args:
        config = Path(args[args.index("--config") + 1])
    domains = load_domains(config)
    now = datetime.now(timezone.utc)

    print("Let's Encrypt cert-limit tracker — %s" % fmt_full(now))
    print("Source: Certificate Transparency via crt.sh (precert+leaf deduped "
          "by issuer+serial;")
    print("issuance time approximated by not_before — LE backdates it ~1h at "
          "most).")
    print("Counts are issuances OBSERVED in crt.sh's CT index — estimates, "
          "not Let's Encrypt's")
    print("internal counters. CT cannot show the issuing account or whether "
          "an issuance was a")
    print("renewal (renewals are exempt from the 50/week cap but counted "
          "here); crt.sh ingestion")
    print("lag can also miss recent certs entirely, so a zero means 'nothing "
          "indexed', not 'nothing issued'.")
    print()

    results = []
    attention = False
    for i, domain in enumerate(domains):
        if i:
            time.sleep(QUERY_DELAY_S)
        certs = fetch_domain(domain)
        if certs is None:
            r = {"domain": domain, "unverified": True, "crossings":
                 ["UNVERIFIED"]}
            attention = True
        else:
            r = analyse(domain, certs, now)
            if r["crossings"]:
                attention = True
        results.append(r)

    for r in results:
        if r.get("unverified"):
            print(r["domain"])
            print("  UNVERIFIED — crt.sh query failed after retries; "
                  "budget position unknown, NOT zero.")
        else:
            for line in block_lines(r):
                print(line)
        print()

    print("Summary (briefing lines):")
    for r in results:
        print("  " + summary_line(r))
    print()
    print("STATUS: %s" % ("ATTENTION" if attention else "OK"))
    return 1 if attention else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
