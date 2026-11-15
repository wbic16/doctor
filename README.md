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
