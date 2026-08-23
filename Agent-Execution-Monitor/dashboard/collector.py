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

    # R1: 内容/参数含密钥
    text = json.dumps(args, ensure_ascii=False)
    for name, pat in SECRET_CONTENT_PATTERNS:
        if pat.search(text):
            alerts.append({
                "rule_id": "R1",
                "severity": "high",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"实时嗅探到疑似密钥（{name}）",
                "event": ev,
            })
            break

    # R3: 异常外联（直连非白名单且无域名说明）
    if et in ("net.connect", "tool.http"):
        host = args.get("host") or args.get("peer", "").rsplit(":", 1)[0]
        if host and host not in ALLOWLIST_HOSTS and not host.startswith("127."):
            alerts.append({
                "rule_id": "R3",
                "severity": "medium",
                "timestamp": ev.get("timestamp"),
                "trace_id": ev.get("trace_id"),
                "span_id": ev.get("span_id"),
                "detail": f"异常外联: {host}",
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


def create_app(events_dir: str, fallback_trace_id: str):
    config = {"events_dir": events_dir, "fallback_trace_id": fallback_trace_id}

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
