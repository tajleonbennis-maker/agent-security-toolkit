#!/bin/bash
# Kiro 被动观察器启动脚本（在你的终端里跑，不要在 WorkBuddy 沙箱里跑）
# v2：默认走 watchdog 守护——观察器被杀自动拉起，同一会话断链续写
#
# 用法:
#   bash kiro/monitor_kiro.sh /path/to/workspace            # 守护模式（推荐）
#   bash kiro/monitor_kiro.sh /path/to/workspace --once …   # 单次直跑 observer
#   停止: touch events/STOP  或  Ctrl-C（watchdog 透传优雅停止）
set -e
WS="${1:?用法: bash kiro/monitor_kiro.sh /path/to/workspace [--once ...]}"
shift || true
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"

if [ "${1:-}" = "--once" ]; then
  shift
  exec "$PY" kiro/observer.py --workspace "$WS" "$@"
fi

echo "=============================================="
echo " Agent 执行监视器 v2 — Kiro 被动观察（守护模式）"
echo " workspace : $WS"
echo " 特性      : 全进程树(含孙进程) / 实时告警落盘"
echo "             崩溃自动拉起 + 会话续写"
echo " 停止      : touch events/STOP 或 Ctrl-C"
echo "=============================================="
exec bash kiro/watchdog.sh "$WS" "$@"
