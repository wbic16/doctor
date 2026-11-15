#!/bin/bash
# Per-minute thermal sampler — appends one line to ~/thermal/thermal.log
# Line: <ISO-8601 local time with offset>, <k10temp Tctl C, one decimal, or NA>, <1-min load avg>
set -u
DIR="$HOME/thermal"
mkdir -p "$DIR"
LOG="$DIR/thermal.log"
TODAY="$(date +%F)"
if [ -s "$LOG" ]; then
  FIRST_DAY="$(head -n 1 "$LOG" | cut -c 1-10)"
  case "$FIRST_DAY" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      if [ "$FIRST_DAY" != "$TODAY" ]; then
        mv -f "$LOG" "$DIR/thermal-$FIRST_DAY.log"
      fi
      ;;
  esac
fi
find "$DIR" -maxdepth 1 -name 'thermal-2*.log' -type f -mtime +30 -delete 2>/dev/null
TEMP="NA"
for H in /sys/class/hwmon/hwmon*; do
  [ -r "$H/name" ] || continue
  if [ "$(cat "$H/name" 2>/dev/null)" = "k10temp" ]; then
    if [ -r "$H/temp1_input" ]; then
      RAW="$(cat "$H/temp1_input" 2>/dev/null)"
      case "$RAW" in
        ''|*[!0-9-]*) : ;;
        *) TEMP="$(awk -v r="$RAW" 'BEGIN { printf "%.1f", r / 1000 }')" ;;
      esac
    fi
    break
  fi
done
LOAD="$(cut -d ' ' -f 1 /proc/loadavg 2>/dev/null || echo NA)"
TS="$(date +%Y-%m-%dT%H:%M:%S%:z)"
printf '%s, %s, %s\n' "$TS" "$TEMP" "$LOAD" >> "$LOG"
