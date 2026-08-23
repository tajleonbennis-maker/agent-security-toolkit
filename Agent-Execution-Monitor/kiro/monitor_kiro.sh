#!/bin/bash
# Kiro 被动观察器启动脚本 v3：一站式启动完整采集栈
#
# 在你的终端里跑（不要在 WorkBuddy 沙箱里跑），因为需要：
#   - lsof 读取其他进程网络/文件描述符
#   - FSEvents 注册系统级文件监视
#
# 用法:
#   bash kiro/monitor_kiro.sh /path/to/workspace [--mitm] [--capture-reads]
#
# 组件：
#   dashboard/collector.py    SSE 实时面板 + 事件总线  (http://127.0.0.1:8787)
#   dashboard/fs_watcher.py   macOS FSEvents 文件监视
#   kiro/observer.py          进程树 + 网络 + 文件轮询 + 实时告警
#   kiro/watchdog.sh          observer 崩溃自动拉起 / 断链续写
#   dashboard/mitm_addon.py   (可选) HTTPS 流量工具调用解析
#
# 停止： bash kiro/monitor_kiro.sh --stop
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-/Users/jatsmith/.workbuddy/binaries/python/versions/3.13.12/bin/python3}"
PIDFILE="${ROOT}/events/.kiro_stack.pids"
COLLECTOR_URL="http://127.0.0.1:8787/ingest"

mkdir -p "${ROOT}/events"

cleanup_and_exit() {
  echo "[stack] 启动失败，清理中..."
  [ -f "$PIDFILE" ] && bash "$0" --stop >/dev/null 2>&1 || true
  exit 1
}

trap cleanup_and_exit ERR

# ---------------- stop mode
if [ "${1:-}" = "--stop" ]; then
  if [ -f "$PIDFILE" ]; then
    while read -r name pid; do
      [ -z "$pid" ] && continue
      if kill -0 "$pid" 2>/dev/null; then
        echo "[stack] 停止 $name (pid $pid)"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.5
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
      fi
    done < "$PIDFILE"
    rm -f "$PIDFILE"
  fi
  # 兜底：杀所有相关子进程
  pkill -f "dashboard/collector.py" 2>/dev/null || true
  pkill -f "dashboard/fs_watcher.py" 2>/dev/null || true
  pkill -f "kiro/observer.py" 2>/dev/null || true
  pkill -f "kiro/watchdog.sh" 2>/dev/null || true
  pkill -f "mitm_addon.py" 2>/dev/null || true
  echo "[stack] 已停止"
  exit 0
fi

WS="${1:?用法: bash kiro/monitor_kiro.sh /path/to/workspace [--mitm] [--capture-reads]}"
shift || true

ENABLE_MITM=0
CAPTURE_READS_ARG=""
TRACE_ID="kiro_live"

while [ $# -gt 0 ]; do
  case "$1" in
    --mitm) ENABLE_MITM=1 ;;
    --capture-reads) CAPTURE_READS_ARG="--capture-reads" ;;
    --trace-id) TRACE_ID="$2"; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
  shift
done

# 避免重复启动
if [ -f "$PIDFILE" ]; then
  old=$(awk '/collector/{print $2}' "$PIDFILE" | head -1)
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
    echo "[stack] 采集栈已在运行 (collector pid $old)"
    echo "[stack] 面板: http://127.0.0.1:8787"
    exit 0
  fi
  rm -f "$PIDFILE"
fi

export COLLECTOR_URL
export TRACE_ID

# ---------------- 1. 启动 collector
COLLECTOR_LOG="${ROOT}/events/collector.log"
"$PY" "${ROOT}/dashboard/collector.py" --port 8787 >"$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!
echo "collector $COLLECTOR_PID" >> "$PIDFILE"
sleep 1
if ! kill -0 $COLLECTOR_PID 2>/dev/null; then
  echo "[stack] collector 启动失败，日志:"
  tail -20 "$COLLECTOR_LOG"
  cleanup_and_exit
fi

# ---------------- 2. 启动 FSEvents 文件监视器
FS_LOG="${ROOT}/events/fs_watcher.log"
"$PY" "${ROOT}/dashboard/fs_watcher.py" "$WS" \
  "/Users/jatsmith/Library/Application Support/Kiro/User" >"$FS_LOG" 2>&1 &
FS_PID=$!
echo "fs_watcher $FS_PID" >> "$PIDFILE"

# ---------------- 3. 启动 MITM 代理（可选，需先安装 CA）
if [ "$ENABLE_MITM" = "1" ]; then
  if ! command -v mitmproxy >/dev/null 2>&1; then
    echo "[stack] 未找到 mitmproxy，跳过 MITM。安装: brew install mitmproxy"
    ENABLE_MITM=0
  else
    MITM_LOG="${ROOT}/events/mitmproxy.log"
    # 仅拦截 Kiro 进程：用 owner 过滤需要 root；这里用透明或普通代理
    # 产品化推荐：系统代理 + PAC 让 Kiro 走 127.0.0.1:8080
    mitmproxy --mode regular@8080 --scripts "${ROOT}/dashboard/mitm_addon.py" \
      --set termlog_verbosity=warn >"$MITM_LOG" 2>&1 &
    MITM_PID=$!
    echo "mitmproxy $MITM_PID" >> "$PIDFILE"
    echo "[stack] MITM 代理已启动: http://127.0.0.1:8080"
    echo "        请把 Kiro 的系统代理设为 127.0.0.1:8080（或安装透明代理）"
  fi
fi

# ---------------- 4. 启动 observer（带 watchdog）
OBSERVER_LOG="${ROOT}/events/observer.log"
COLLECTOR_ARG=""
[ -n "$COLLECTOR_URL" ] && COLLECTOR_ARG="--collector $COLLECTOR_URL"

bash "${ROOT}/kiro/watchdog.sh" "$WS" "$TRACE_ID" \
  --agent-name Kiro $COLLECTOR_ARG $CAPTURE_READS_ARG >"$OBSERVER_LOG" 2>&1 &
WATCHDOG_PID=$!
echo "watchdog $WATCHDOG_PID" >> "$PIDFILE"

# ---------------- 5. 打开浏览器面板
sleep 2
if command -v open >/dev/null 2>&1; then
  open "http://127.0.0.1:8787" || true
fi

echo "=============================================="
echo " Agent 执行监视器 v3 — 采集栈已启动"
echo " 面板      : http://127.0.0.1:8787"
echo " workspace : $WS"
echo " trace_id  : $TRACE_ID"
echo " PID 文件  : $PIDFILE"
echo " 组件      : collector($COLLECTOR_PID) fs_watcher($FS_PID) watchdog($WATCHDOG_PID)"
[ "$ENABLE_MITM" = "1" ] && echo " MITM      : 127.0.0.1:8080（已启用）"
echo " 停止      : bash kiro/monitor_kiro.sh --stop"
echo "=============================================="
