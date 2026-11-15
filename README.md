# doctor

Thermal sampler for aletheia-core (ranch node).

`sample.sh` appends one line per run to `~/thermal/thermal.log`:
an ISO-8601 local timestamp, the k10temp Tctl temperature (degrees C,
one decimal, or NA), and the 1-minute load average. The log rotates
daily to `thermal-<date>.log`; rotated logs older than 30 days are
deleted by the sampler itself.

Runs every minute from wbic16's crontab on aletheia-core:

    * * * * * /home/wbic16/thermal/sample.sh

Live tool: `/home/wbic16/thermal/sample.sh` on aletheia-core.
This repo is its versioned home (repo-coverage census, 2026-11-15).

## cert_limits.py — Let's Encrypt cert-limit tracker

`cert_limits.py` reads Certificate Transparency via crt.sh for every
domain in `domains.txt` and reports the Let's Encrypt budget position
per registered domain: issuances observed in the trailing 168 hours
vs the 50/week cap (per eTLD+1 — subdomains share the budget),
duplicate name-sets vs the 5/week cap, when the next slot frees, and
live certs expiring within 21 days. Counts are crt.sh-index estimates
(precert+leaf deduped by issuer+serial), not LE's internal counters —
see the script header for the honesty notes, including crt.sh
ingestion lag.

Run it:

    python3 cert_limits.py            # uses domains.txt beside it
    python3 cert_limits.py --config other-domains.txt

Exit code is 0 when every domain verified clean, non-zero when a
domain is UNVERIFIED (crt.sh query failed after retries) or a
threshold is crossed (>=80% of the weekly cap, a name-set at >=4
duplicates, a live cert <14 days to expiry) — so a Jenkins job can
gate on it directly. A future Jenkins job (planned, not yet created)
would run, on a ranch node:

    python3 /path/to/doctor/cert_limits.py

and fail the build on a non-zero exit, surfacing the report; the
summary block at the end of the output is sized for briefing lines.
