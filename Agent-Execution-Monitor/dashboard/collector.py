#!/usr/bin/env python3
"""
Agent 执行监视器 —— 实时事件收集器 + SSE 广播 + 本地仪表板

职责：
1. 接收各采集器通过 HTTP POST /ingest 上报的事件（NDJSON 或单条 JSON）
2. 把事件追加到本地 NDJSON 文件（实时落盘，断点可续）
3. 通过 /events SSE 向浏览器实时推送
4. 提供 / 网页仪表板
5. 轻量实时规则：命中密钥模式或越界外联时立即广播 alert

启动：
  python3 dashboard/collector.py [--port 8787] [--events-dir events]
"""
import argparse
import json
import os
import queue
import re
import secrets
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

ROOT = Path(__file__).resolve().parents[1]
app = Flask(__name__)

# 全局状态
STATE = {
    "clients": [],          # SSE 订阅队列
    "events": [],           # 最近 2000 条（内存缓存）
    "alerts": [],           # 最近 200 条实时告警
    "counters": {},         # 按 event_type 计数
    "last": None,           # 最新事件时间
}
LOCK = threading.Lock()

SECRET_CONTENT_PATTERNS = [
    ("password-assign", re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?[\w\-./!@#$%^&*]{8,}")),
    ("sshpass", re.compile(r"(?i)sshpass\s+.*\-(p|P)\s+\S+")),
    ("aws-key", re.compile(r"(?i)(AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})")),
    ("private-key", re.compile(r"(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY")),
    ("api-key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-z0-9]{32,}")),
]

ALLOWLIST_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0"}

# 危险命令（工具审计：execute_bash/run_command 命令内容）
DANGEROUS_COMMAND_PATTERNS = [
    ("递归删除", re.compile(r"(?i)\brm\s+-[a-z]*[rf][a-z]*[rf][a-z]*\b")),
    ("管道执行远程脚本", re.compile(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(ba|z|k|da)?sh\b")),
    ("危险权限", re.compile(r"(?i)\bchmod\s+(-R\s+)?777\b")),
    ("磁盘擦除", re.compile(r"(?i)\bdd\s+.*\bof=/dev/")),
    ("格式化磁盘", re.compile(r"(?i)\bmkfs")),
    ("递归删除目录", re.compile(r"(?i)\brmdir\s+/s\b")),
    ("覆盖系统文件", re.compile(r"(?i)\b(sudo\s+)?(echo|cat|tee)\b.*>\s*/etc/")),
]

# 数据外泄检测（llm.request 请求体里出现的敏感路径/内容）
SENSITIVE_EXFIL_PATTERNS = [
    ("SSH密钥路径", re.compile(r"\.ssh/|id_rsa|id_ed25519|authorized_keys")),
    ("git凭证", re.compile(r"\.gitconfig|\.git-credentials")),
    ("云凭证路径", re.compile(r"\.aws/|\.gnupg/|\.config/gcloud|\.kube/")),
    ("环境变量文件", re.compile(r"\.env\b")),
    ("私钥内容", re.compile(r"BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY")),
    ("密码管理器", re.compile(r"\.netrc|Keychains|keychain")),
]

# 越界文件读取（read_file 读敏感文件）
SENSITIVE_READ_PATHS = [
    ("SSH密钥", re.compile(r"\.ssh/")),
    ("git凭证", re.compile(r"\.gitconfig|\.git-credentials")),
    ("云凭证", re.compile(r"\.aws/|\.gnupg/")),
    ("系统账号", re.compile(r"/etc/(passwd|shadow|sudoers)")),
    ("环境变量", re.compile(r"\.env\b")),
]


def chain_hash(prev_hash: str, event: dict) -> str:
    """与 runtime/trace.py 保持一致的哈希算法。"""
    import hashlib

    def _canonical(obj):
        if isinstance(obj, dict):
            return {k: _canonical(v) for k, v in sorted(obj.items()) if v is not None}
        if isinstance(obj, list):
            return [_canonical(x) for x in obj]
        return obj

    payload = json.dumps(_canonical(event.get("evidence") or {}), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}|{payload}".encode("utf-8")).hexdigest()


def make_event(trace_id: str, event_type: str, span_id: str, parent_span_id: str,
               actor: dict, action: dict, source: str = "dashboard", extra: dict = None) -> dict:
    """构造一条符合 schema 0.1 的事件。"""
    now = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    ev = {
        "schema_version": "0.1",
        "trace_id": trace_id,
        "span_id": span_id or secrets.token_hex(16),
        "parent_span_id": parent_span_id,
        "timestamp": now,
        "event_type": event_type,
        "source": source,
        "actor": actor or {"type": "unknown"},
        "action": {
            "name": action.get("name", event_type),
            "arguments_redacted": action.get("arguments_redacted", {}),
            "result_summary": action.get("result_summary", {}),
            "summary": action.get("summary", ""),
        },
        "evidence": {
            "integrity": "sha256-chain",
            "prev_hash": "",
            "hash": "",
        },
    }
    if extra:
        ev.update(extra)
    return ev


def _classify_alert(ev: dict) -> list:
    """实时规则，返回若干 alert 字典。"""
    alerts = []
    et = ev.get("event_type", "")
    args = ev.get("action", {}).get("arguments_redacted", {})

    # R1: 内容/参数含密钥（重点：明文密码命令，脱敏显示）
    text = json.dumps(args, ensure_ascii=False)
    for name, pat in SECRET_CONTENT_PATTERNS:
        if pat.search(text):
            detail = f"实时嗅探到疑似密钥（{name}）"
            # 工具调用命令 → 显示工具名 + 脱敏后的命令，让告警可定位
            if et == "tool.invoke":
                tool_name = ev.get("action", {}).get("name", "")
                cmd = args.get("command", "") if isinstance(args, dict) else ""
                if cmd:
                    redacted = re.sub(
                        r'(-p\s+["\']?)[^"\'\s]+', r'\1[REDACTED]', cmd, flags=re.I)
                    redacted = re.sub(
                        r'(password|passwd|pwd|secret|token)\s*[:=]\s*["\']?[^\s"\']+',
                        r'\1=[REDACTED]', redacted, flags=re.I)
                    detail = (f"明文密码命令（{name}）：{tool_name} → "
                              f"{redacted[:140]}")
            alerts.append({
                "rule_id": "R1",
                "severity": "high",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": detail,
                "event": ev,
            })
            break

    # R3: 异常外联（绕过代理直连公网，peer_kind=direct）
    if et == "net.connect":
        peer_kind = args.get("peer_kind", "")
        peer = args.get("peer", "")
        if peer_kind == "direct":
            alerts.append({
                "rule_id": "R3",
                "severity": "medium",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"异常外联(绕过代理): {peer}",
                "event": ev,
            })

    # R2: 越界文件读取/写入（按 workspace 参数判断）
    if et in ("fs.read", "fs.write", "fs.create"):
        path = args.get("path", "")
        workspace = args.get("workspace", "")
        if workspace and path and not path.startswith(workspace):
            alerts.append({
                "rule_id": "R2",
                "severity": "medium",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"越界文件操作: {path}",
                "event": ev,
            })

    # R4: 危险命令（工具审计：execute_bash/run_command 含危险操作）
    if et == "tool.invoke":
        cmd = args.get("command", "") if isinstance(args, dict) else ""
        if cmd:
            for name, pat in DANGEROUS_COMMAND_PATTERNS:
                if pat.search(cmd):
                    alerts.append({
                        "rule_id": "R4",
                        "rule_name": "危险命令",
                        "severity": "high",
                        "timestamp": ev.get("timestamp"),
                        "trace_id": ev.get("trace_id"),
                        "span_id": ev.get("span_id"),
                        "detail": f"危险命令（{name}）：{cmd[:120]}",
                        "event": ev,
                    })
                    break

    # 越界读取敏感文件（工具审计：read_file/grep_search 读敏感文件）
    if et == "tool.invoke":
        path = args.get("path", "") if isinstance(args, dict) else ""
        if path:
            for name, pat in SENSITIVE_READ_PATHS:
                if pat.search(path):
                    alerts.append({
                        "rule_id": "R1",
                        "rule_name": "敏感文件读取",
                        "severity": "high",
                        "timestamp": ev.get("timestamp"),
                        "trace_id": ev.get("trace_id"),
                        "span_id": ev.get("span_id"),
                        "detail": f"读取敏感文件（{name}）：{path[:120]}",
                        "event": ev,
                    })
                    break

    # 数据外泄检测（llm.request 请求体含敏感路径/内容）
    if et == "llm.request":
        for name, pat in SENSITIVE_EXFIL_PATTERNS:
            if pat.search(text):
                alerts.append({
                    "rule_id": "R1",
                    "rule_name": "数据外泄",
                    "severity": "high",
                    "timestamp": ev.get("timestamp"),
                    "trace_id": ev.get("trace_id"),
                    "span_id": ev.get("span_id"),
                    "detail": f"请求体含敏感信息（{name}）→ 可能外泄给大模型",
                    "event": ev,
                })
                break

    return alerts


def _append_to_file(path: Path, lines: list):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def _broadcast(obj: dict):
    dead = []
    with LOCK:
        for q in STATE["clients"]:
            try:
                q.put_nowait(obj)
            except queue.Full:
                dead.append(q)
        STATE["clients"] = [q for q in STATE["clients"] if q not in dead]


def ingest_event(ev: dict, config: dict):
    """核心入口：接收事件、校验/补链、落盘、广播、实时规则。"""
    et = ev.get("event_type", "unknown")
    trace_id = ev.get("trace_id") or config["fallback_trace_id"]
    ev.setdefault("trace_id", trace_id)

    # 维护哈希链（简单模式：按文件内顺序，每条事件只依赖前一条 hash）
    chain_file = Path(config["events_dir"]) / f"{trace_id}.ndjson"
    prev = "GENESIS"
    if chain_file.exists():
        try:
            with open(chain_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size:
                    f.seek(max(0, size - 4096))
                    last_line = f.read().decode("utf-8", errors="ignore").strip().split("\n")[-1]
                    last_ev = json.loads(last_line)
                    prev = (last_ev.get("evidence") or {}).get("hash", "GENESIS")
        except Exception:
            pass

    ev.setdefault("evidence", {})
    if not ev["evidence"].get("hash"):
        # 无 hash 的事件（本地 observer/mitmproxy/fs_watcher）→ 本地续链
        ev["evidence"]["prev_hash"] = prev
        ev["evidence"]["hash"] = chain_hash(prev, ev)
    # 已有 hash 的事件（server/agent.py 上报）→ 保留其原始哈希链，不重算

    # 落盘
    _append_to_file(chain_file, [ev])

    # 内存状态 + 广播
    with LOCK:
        STATE["events"].append(ev)
        if len(STATE["events"]) > 2000:
            STATE["events"] = STATE["events"][-2000:]
        STATE["counters"][et] = STATE["counters"].get(et, 0) + 1
        STATE["last"] = ev.get("timestamp")

    _broadcast({"kind": "event", "data": ev})

    # 实时告警
    for alert in _classify_alert(ev):
        alert["_id"] = secrets.token_hex(8)
        with LOCK:
            STATE["alerts"].append(alert)
            if len(STATE["alerts"]) > 200:
                STATE["alerts"] = STATE["alerts"][-200:]
        _append_to_file(Path(config["events_dir"]) / f"{trace_id}_alerts.ndjson", [alert])
        _broadcast({"kind": "alert", "data": alert})


def _load_history(events_dir: str):
    """启动时从 events 目录加载历史事件，让 BOSS 视图重启后仍有数据。"""
    evdir = Path(events_dir)
    if not evdir.is_dir():
        return
    loaded = []
    for fn in sorted(evdir.glob("*.ndjson")):
        if fn.name.endswith("_alerts.ndjson"):
            continue
        try:
            with open(fn, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        loaded.append(ev)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    if not loaded:
        return
    loaded.sort(key=lambda e: e.get("timestamp", "") or "")
    loaded = loaded[-3000:]
    with LOCK:
        STATE["events"] = loaded
        for ev in loaded:
            et = ev.get("event_type", "unknown")
            STATE["counters"][et] = STATE["counters"].get(et, 0) + 1
        STATE["last"] = loaded[-1].get("timestamp") if loaded else None


def create_app(events_dir: str, fallback_trace_id: str):
    config = {"events_dir": events_dir, "fallback_trace_id": fallback_trace_id}
    _load_history(events_dir)

    @app.route("/ingest", methods=["POST"])
    def ingest():
        ctype = request.headers.get("Content-Type", "")
        items = []
        if "ndjson" in ctype or "x-ndjson" in ctype:
            # ndjson 批量（server/agent.py 上报格式，多行 JSON）
            raw = request.get_data(as_text=True)
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            try:
                payload = request.get_json(force=True, silent=True) or {}
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 400
            # 支持单条或数组
            items = payload if isinstance(payload, list) else [payload]

        n = 0
        for ev in items:
            if not isinstance(ev, dict):
                continue
            ingest_event(ev, config)
            n += 1
        return jsonify({"ok": True, "ingested": n})

    @app.route("/events")
    def events():
        def stream():
            q = queue.Queue(maxsize=200)
            with LOCK:
                STATE["clients"].append(q)
                # 推送历史最近 100 条 + 最近 20 告警
                for ev in STATE["events"][-100:]:
                    yield f"data: {json.dumps({'kind':'event','data':ev}, ensure_ascii=False)}\n\n"
                for a in STATE["alerts"][-20:]:
                    yield f"data: {json.dumps({'kind':'alert','data':a}, ensure_ascii=False)}\n\n"
            try:
                while True:
                    obj = q.get(timeout=30)
                    yield f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'kind':'ping'}, ensure_ascii=False)}\n\n"
            finally:
                with LOCK:
                    if q in STATE["clients"]:
                        STATE["clients"].remove(q)

        return Response(stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/state")
    def api_state():
        with LOCK:
            return jsonify({
                "counters": STATE["counters"].copy(),
                "clients": len(STATE["clients"]),
                "alerts": len(STATE["alerts"]),
                "last": STATE["last"],
            })

    @app.route("/api/events")
    def api_events():
        limit = min(int(request.args.get("limit", 100)), 500)
        with LOCK:
            return jsonify(STATE["events"][-limit:])

    @app.route("/api/alerts")
    def api_alerts():
        with LOCK:
            return jsonify(STATE["alerts"])

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/boss")
    def boss():
        return render_template_string(BOSS_HTML)

    return app


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent 执行监视器 — 实时面板</title>
<style>
  :root { --bg:#f6f7f9; --panel:#fff; --text:#1f2328; --muted:#656d76; --accent:#0969da; --red:#cf222e; --orange:#bc4c00; --green:#1a7f37; }
  body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
  header { background:var(--panel); border-bottom:1px solid #d1d9e0; padding:16px 24px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:10; }
  h1 { margin:0; font-size:18px; }
  .status { display:flex; gap:12px; align-items:center; font-size:13px; color:var(--muted); }
  .badge { background:#eaeef2; padding:3px 8px; border-radius:12px; }
  .alert-badge { background:#ffebe9; color:var(--red); font-weight:600; }
  main { display:grid; grid-template-columns: 320px 1fr; gap:16px; padding:16px; }
  .panel { background:var(--panel); border:1px solid #d1d9e0; border-radius:10px; padding:14px; }
  .panel h2 { margin:0 0 10px; font-size:14px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; }
  .metric { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #f0f0f0; font-size:13px; }
  .metric:last-child { border-bottom:none; }
  .stream { max-height: calc(100vh - 180px); overflow:auto; }
  .event { border-left:3px solid #d1d9e0; padding:8px 10px; margin-bottom:6px; border-radius:0 6px 6px 0; background:#fafafa; font-size:12px; }
  .event.tool { border-left-color:var(--accent); }
  .event.net { border-left-color:var(--orange); }
  .event.fs { border-left-color:var(--green); }
  .event.conversation { border-left-color:#7c3aed; background:#f5f3ff; }
  .event.llm { border-left-color:#0a9396; background:#f0fdfa; }
  .event.alert { border-left-color:var(--red); background:#fff6f5; }
  .ts { color:var(--muted); font-family:monospace; }
  .type { font-weight:600; color:var(--text); }
  .source { color:var(--muted); }
  .detail { margin-top:4px; word-break:break-all; }
  pre { background:#f3f4f6; padding:8px; border-radius:6px; overflow:auto; max-height:200px; margin:6px 0 0; }
  .red-dot { display:inline-block; width:8px; height:8px; background:var(--red); border-radius:50%; animation:pulse 1s infinite; }
  @keyframes pulse { 0%{opacity:1} 50%{opacity:.4} 100%{opacity:1} }
  @media (max-width:900px){ main{grid-template-columns:1fr;} }
</style>
</head>
<body>
<header>
  <h1>🛡️ Agent 执行监视器</h1>
  <div class="status">
    <span id="conn" class="badge">⏳ 连接中…</span>
    <span class="badge">采集器在线: <b id="clients">0</b></span>
    <span class="badge alert-badge">🚨 告警: <b id="alertCount">0</b></span>
    <span class="badge">最后事件: <span id="last">—</span></span>
  </div>
</header>
<main>
  <aside>
    <div class="panel">
      <h2>事件统计</h2>
      <div id="counters"></div>
    </div>
    <div class="panel" style="margin-top:16px">
      <h2>实时告警</h2>
      <div id="alerts" class="stream"></div>
    </div>
  </aside>
  <section class="panel">
    <h2>事件流</h2>
    <div id="events" class="stream"></div>
  </section>
</main>
<script>
const host = location.host;
const es = new EventSource(`/events`);
es.onopen = () => document.getElementById('conn').textContent = '🟢 实时连接';
es.onerror = () => document.getElementById('conn').textContent = '🔴 断开';

function fmtTime(ts){ if(!ts) return '-'; const d=new Date(ts); return d.toLocaleTimeString('zh-CN',{hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0'); }
function esc(s){ return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function kindClass(t){ if(t.startsWith('tool.')) return 'tool'; if(t.startsWith('fs.')) return 'fs'; if(t.startsWith('net.')||t.startsWith('session.')) return 'net'; if(t.startsWith('conversation.')) return 'conversation'; if(t.startsWith('llm.')) return 'llm'; if(t==='alert') return 'alert'; return ''; }

function renderEvent(msg){
  const e = msg.data;
  const div = document.createElement('div');
  div.className = 'event ' + kindClass(e.event_type || msg.kind);
  const act = e.action || {};
  const args = act.arguments_redacted || {};
  let summary = act.summary || '';
  if(!summary && args.peer) summary = args.peer;
  if(!summary && args.path) summary = args.path;
  if(!summary && args.method) summary = `${args.method} ${args.host||args.url||''}`;
  if(!summary && args.tool_name) summary = args.tool_name;
  let extra = '';
  const payload = Object.keys(args).length ? JSON.stringify(args, null, 2) : '';
  if(payload) extra += `<pre>${esc(payload)}</pre>`;
  div.innerHTML = `<div><span class="ts">${fmtTime(e.timestamp)}</span> <span class="type">${esc(e.event_type||msg.kind)}</span> <span class="source">${esc(e.source||'')}</span></div><div class="detail">${esc(summary)}</div>${extra}`;
  const box = document.getElementById('events');
  box.prepend(div);
  while(box.children.length > 300) box.lastChild.remove();
}

function renderAlert(a){
  const div = document.createElement('div');
  div.className = 'event alert';
  div.innerHTML = `<div><span class="ts">${fmtTime(a.timestamp)}</span> <span class="type">${esc(a.rule_id)}</span> <b>${esc(a.severity)}</b></div><div class="detail">${esc(a.detail)}</div>`;
  const box = document.getElementById('alerts');
  box.prepend(div);
  while(box.children.length > 50) box.lastChild.remove();
  document.getElementById('alertCount').innerHTML = '<span class="red-dot"></span> ' + box.children.length;
}

es.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  if(msg.kind === 'event') renderEvent(msg);
  if(msg.kind === 'alert') renderAlert(msg.data);
};

async function refreshState(){
  const r = await fetch('/api/state');
  const s = await r.json();
  document.getElementById('clients').textContent = s.clients;
  document.getElementById('last').textContent = fmtTime(s.last);
  const c = document.getElementById('counters');
  c.innerHTML = Object.entries(s.counters).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<div class="metric"><span>${esc(k)}</span><b>${v}</b></div>`).join('');
}
setInterval(refreshState, 3000);
refreshState();
</script>
</body>
</html>
"""


BOSS_HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent 使用总览 — BOSS 视图</title>
<style>
  :root { --bg:#f2f4f7; --panel:#fff; --text:#1a1f26; --muted:#6b7280; --accent:#2563eb; --red:#dc2626; --orange:#d97706; --green:#16a34a; --purple:#7c3aed; --border:#e5e7eb; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); }
  header { background:var(--panel); border-bottom:1px solid var(--border); padding:14px 24px; display:flex; align-items:center; gap:16px; position:sticky; top:0; z-index:10; }
  h1 { margin:0; font-size:19px; font-weight:600; }
  .nav { margin-left:auto; display:flex; gap:8px; font-size:13px; }
  .nav a { text-decoration:none; color:var(--muted); padding:5px 12px; border-radius:8px; }
  .nav a.active { background:#eef2ff; color:var(--accent); font-weight:600; }
  .stats { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; padding:16px 24px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px; }
  .stat .label { font-size:12px; color:var(--muted); margin-bottom:6px; }
  .stat .value { font-size:26px; font-weight:700; }
  .stat.warn .value { color:var(--red); }
  main { padding:0 24px 40px; }
  .task { background:var(--panel); border:1px solid var(--border); border-radius:14px; margin-bottom:16px; overflow:hidden; }
  .task-head { padding:14px 18px; border-bottom:1px solid var(--border); display:flex; align-items:baseline; gap:12px; }
  .task-head .time { font-size:12px; color:var(--muted); white-space:nowrap; }
  .task-head .instruction { font-size:15px; font-weight:600; flex:1; }
  .task-head .risk { font-size:12px; background:#fef2f2; color:var(--red); padding:3px 10px; border-radius:12px; font-weight:600; }
  .task-body { padding:14px 18px; }
  .row { display:flex; gap:8px; align-items:flex-start; margin-bottom:10px; font-size:13px; }
  .row .tag { flex-shrink:0; width:88px; color:var(--muted); font-size:12px; padding-top:1px; }
  .row .content { flex:1; line-height:1.7; }
  .chip { display:inline-block; background:#f3f4f6; border:1px solid var(--border); border-radius:6px; padding:1px 8px; margin:2px 3px 2px 0; font-size:12px; font-family:ui-monospace,monospace; }
  .chip.model { background:#f5f3ff; border-color:#ddd6fe; color:var(--purple); }
  .chip.tool { background:#eef2ff; border-color:#c7d2fe; color:var(--accent); }
  .chip.file { background:#f0fdf4; border-color:#bbf7d0; color:var(--green); }
  .chip.ext { background:#fffbeb; border-color:#fde68a; color:var(--orange); }
  .chip.read { background:#f0f9ff; border-color:#bae6fd; color:#0369a1; }
  .risk-section { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:16px 18px; margin-bottom:16px; }
  .risk-section h2 { margin:0 0 10px; font-size:15px; }
  .risk-item { font-size:13px; padding:6px 0; border-bottom:1px solid #f5f5f5; }
  .risk-item:last-child { border-bottom:none; }
  .risk-item .r1 { color:var(--red); font-weight:600; }
  .risk-item .r4 { color:var(--orange); font-weight:600; }
  .empty { text-align:center; color:var(--muted); padding:60px 0; font-size:14px; }
  @media (max-width:900px) { .stats { grid-template-columns:repeat(3,1fr); } }
</style>
</head>
<body>
<header>
  <h1>🤖 Agent 使用总览</h1>
  <div class="nav">
    <a href="/boss" class="active">BOSS 视图</a>
    <a href="/">原始事件</a>
  </div>
</header>

<div class="stats" id="stats"></div>
<main>
  <div class="risk-section" id="riskSummary" style="display:none"></div>
  <div id="tasks"></div>
</main>

<script>
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtTime = ts => { if(!ts) return ''; const d=new Date(ts); return isNaN(d)? String(ts).slice(11,19) : d.toLocaleTimeString('zh-CN',{hour12:false}); };
const isNoiseFs = p => !p || p.includes('Application Support') || p.includes('Library/Caches') || p.includes('.git/objects');

async function load(){
  const [evRes, alRes] = await Promise.all([
    fetch('/api/events?limit=3000').then(r=>r.json()),
    fetch('/api/alerts').then(r=>r.json())
  ]);
  const events = Array.isArray(evRes) ? evRes : [];
  const alerts = Array.isArray(alRes) ? alRes : [];
  renderStats(events, alerts);
  renderRisk(alerts);
  renderTasks(events, alerts);
}

function renderStats(events, alerts){
  const instructions = getInstructions(events);
  const toolCalls = events.filter(e=>e.event_type==='tool.invoke').length;
  const llmCalls = events.filter(e=>e.event_type==='llm.request').length;
  const fileOps = events.filter(e=>e.event_type.startsWith('fs.') && !isNoiseFs(e.action?.arguments_redacted?.path)).length;
  const externals = collectExternals(events).size;
  const riskCount = alerts.filter(a=>a.rule_id==='R1'||a.rule_id==='R4').length;
  const cards = [
    ['指令数', instructions.length, ''],
    ['工具调用', toolCalls, ''],
    ['大模型调用', llmCalls, ''],
    ['文件操作', fileOps, ''],
    ['外部资源', externals, ''],
    ['高风险告警', riskCount, 'warn'],
  ];
  document.getElementById('stats').innerHTML = cards.map(([l,v,cls])=>
    `<div class="stat ${cls}"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');
}

function getInstructions(events){
  return events.filter(e => {
    if(e.event_type !== 'conversation.user') return false;
    const p = e.action?.arguments_redacted?.preview || '';
    return !p.startsWith('You are Kiro') && p.trim().length > 0;
  });
}

function collectExternals(events){
  const s = new Set();
  events.forEach(e => {
    if(!['net.connect','tool.http'].includes(e.event_type)) return;
    const ar = e.action?.arguments_redacted || {};
    const host = ar.host || (ar.peer||'').split(':')[0];
    if(host && !host.startsWith('127.') && !host.includes('telemetry') && !host.includes('download.kiro')) s.add(host);
  });
  return s;
}

function extractModel(ev){
  const ar = ev.action?.arguments_redacted || {};
  const s = JSON.stringify(ar);
  const m = s.match(/"modelId"\s*:\s*"([^"]+)"/) || s.match(/"model"\s*:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

function renderTasks(events, alerts){
  const instructions = getInstructions(events);
  const sorted = [...events].sort((a,b)=>String(a.timestamp||'').localeCompare(String(b.timestamp||'')));
  const box = document.getElementById('tasks');
  if(!instructions.length){
    box.innerHTML = '<div class="empty">暂无指令记录 — 等用户在 Agent 中发起对话后，这里会按指令展示完整任务过程</div>';
    return;
  }
  // 每个指令一个任务（该指令到下一个指令之间的时间段）
  const html = instructions.map((ins, i)=>{
    const t0 = ins.timestamp;
    const t1 = instructions[i+1]?.timestamp;
    const evs = sorted.filter(e => e.timestamp && e.timestamp >= t0 && (!t1 || e.timestamp < t1));
    const models = new Set(); const tools = []; const reads = new Set(); const writes = new Set(); const exts = new Set();
    evs.forEach(e=>{
      const ar = e.action?.arguments_redacted || {};
      if(e.event_type==='llm.request'){ const m=extractModel(e); if(m) models.add(m); }
      else if(e.event_type==='tool.invoke'){ if(e.action?.name) tools.push(e.action.name); }
      else if(e.event_type==='fs.read'){ if(!isNoiseFs(ar.path)) reads.add(ar.path); }
      else if(['fs.write','fs.create'].includes(e.event_type)){ if(!isNoiseFs(ar.path)) writes.add(ar.path); }
      else if(['net.connect','tool.http'].includes(e.event_type)){ const h=ar.host||(ar.peer||'').split(':')[0]; if(h&&!h.startsWith('127.')&&!h.includes('telemetry')&&!h.includes('download.kiro')) exts.add(h); }
    });
    const riskCount = alerts.filter(a => a.timestamp && a.timestamp >= t0 && (!t1 || a.timestamp < t1) && (a.rule_id==='R1'||a.rule_id==='R4')).length;
    const preview = (ins.action?.arguments_redacted?.preview || '').replace(/\n/g,' ');
    return `<div class="task">
      <div class="task-head">
        <span class="time">${fmtTime(t0)}</span>
        <span class="instruction">💬 ${esc(preview.slice(0,80))}</span>
        ${riskCount ? `<span class="risk">⚠️ ${riskCount} 风险</span>` : ''}
      </div>
      <div class="task-body">
        ${models.size ? `<div class="row"><span class="tag">大模型</span><span class="content">${[...models].map(m=>`<span class="chip model">${esc(m)}</span>`).join('')}</span></div>` : ''}
        ${tools.length ? `<div class="row"><span class="tag">执行操作</span><span class="content">${[...new Set(tools)].map(t=>`<span class="chip tool">🔧 ${esc(t)}</span>`).join('')}</span></div>` : ''}
        ${reads.size ? `<div class="row"><span class="tag">读取文件</span><span class="content">${[...reads].slice(0,8).map(f=>`<span class="chip read">${esc(f.split('/').slice(-2).join('/'))}</span>`).join('')}</span></div>` : ''}
        ${writes.size ? `<div class="row"><span class="tag">写入文件</span><span class="content">${[...writes].slice(0,8).map(f=>`<span class="chip file">✍️ ${esc(f.split('/').slice(-2).join('/'))}</span>`).join('')}</span></div>` : ''}
        ${exts.size ? `<div class="row"><span class="tag">外部资源</span><span class="content">${[...exts].slice(0,10).map(h=>`<span class="chip ext">🌐 ${esc(h)}</span>`).join('')}</span></div>` : ''}
      </div>
    </div>`;
  }).join('');
  box.innerHTML = html;
}

function renderRisk(alerts){
  const box = document.getElementById('riskSummary');
  const risky = alerts.filter(a=>a.rule_id==='R1'||a.rule_id==='R4').slice(0,30);
  if(!risky.length){ box.style.display='none'; return; }
  box.style.display='block';
  box.innerHTML = `<h2>🚨 风险告警（${risky.length} 条）</h2>` +
    risky.map(a=>`<div class="risk-item"><span class="${a.rule_id==='R1'?'r1':'r4'}">[${a.rule_id}]</span> ${fmtTime(a.timestamp)} — ${esc(a.detail||'').slice(0,120)}</div>`).join('');
}

load();
setInterval(load, 5000);
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--events-dir", default=str(ROOT / "events"))
    ap.add_argument("--fallback-trace-id", default="live")
    args = ap.parse_args()

    create_app(args.events_dir, args.fallback_trace_id)
    print(f"[collector] 监听 http://127.0.0.1:{args.port}/")
    print(f"[collector] ingest endpoint: POST http://127.0.0.1:{args.port}/ingest")
    app.run(host="127.0.0.1", port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
