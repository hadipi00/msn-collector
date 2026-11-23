#!/usr/bin/env bash
# MSN Collector — catch-up scheduler daemon.
# - runs one cycle immediately if the last one is older than INTERVAL (catch-up)
# - then keeps a strict 2h cadence (timestamp written at cycle START, no drift)
# - chunked sleep -> resilient to VM suspension / clock jumps
# - single instance guaranteed via flock
# Started by launch_daemon.py (double-fork) / ensure.sh
set -u
cd "$(dirname "$0")"
INTERVAL=7200

echo $$ > .scheduler.pid
exec 9>.scheduler.lock
flock -n 9 || { echo "[scheduler] another instance holds the lock — exiting"; exit 0; }
echo "[scheduler] started $(date -u '+%F %T') UTC (pid $$)"

sleep_until() {
  while :; do
    last=$(cat .last_cycle_ts 2>/dev/null || echo 0)
    now=$(date +%s)
    wait=$(( last + INTERVAL - now ))
    [ "$wait" -le 0 ] && return 0
    [ "$wait" -gt 60 ] && wait=60
    sleep "$wait"
  done
}

while true; do
  sleep_until
  date +%s > .last_cycle_ts
  # log rotation (keep tail)
  if [ -f scheduler.log ] && [ "$(stat -c%s scheduler.log)" -gt 5000000 ]; then
    tail -c 500000 scheduler.log > scheduler.log.t && mv scheduler.log.t scheduler.log
  fi
  echo "[scheduler] cycle start $(date -u '+%F %T') UTC" >> scheduler.log
  bash run.sh >> scheduler.log 2>&1
done
