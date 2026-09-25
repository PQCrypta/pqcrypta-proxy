#!/usr/bin/env bash
# The measurement-window study again, on the fixed backend, once the re-run
# queue (launch-rerun.sh, 20260925_132019) has finished. Same binary as that
# queue, so the page's two runs describe one build. Packaged into
# out/publish-$STAMP/ with its own .done list.
set -uo pipefail
cd /root/bench
until grep -q '^all ' /root/bench/out/publish-20260925_132019.done 2>/dev/null; do sleep 300; done
STAMP=$(date +%Y%m%d_%H%M%S)
PUB=/root/bench/out/publish-$STAMP
mkdir -p "$PUB"
BIN=/root/bench/pqc-fa8556d2 RES=/root/bench/out/window-$STAMP ./window-study.sh >/dev/null 2>&1
if grep -q '^########## done' /root/bench/out/window-$STAMP/run.log; then
  BINARY=/root/bench/pqc-fa8556d2 python3 export-study.py window out/window-$STAMP "$PUB/window-$STAMP" 6d75ab9 >/dev/null \
    && echo "window-$STAMP $(date -Is)" >> "$PUB.done"
fi
echo "all $(date -Is)" >> "$PUB.done"
echo "$PUB" > /root/bench/out/queue-window.stamp
