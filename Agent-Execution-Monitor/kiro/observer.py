#!/usr/bin/env python3
"""Kiro 被动观察器 v2：监视第三方 AI IDE（Kiro）的系统级行为。

v2 针对实战（2026-08-23 kiro_agent_test 部署监视战）暴露的问题全面升级：

  盲区修复  全进程树追踪：不只 Kiro.app 前缀进程，凡 pid→ppid 链可达
            Kiro 种子进程的都是目标（Kiro 终端里跑的 go/git/ssh 孙进程
            全部入镜）；ps 不可用时 libproc 降级也带 ppid（PROC_PIDTBSDINFO）。
            另支持 --seed-pid / --seed-pattern 监视任意 Agent，产品化通用。
  网络归属  lsof 连接按"当轮实时进程树"归属，不等 spawn 事件先落账——
            短命孙进程（git push / ssh）的连接不再漏拍。
  实时告警  内嵌规则引擎：R1/R2/R3 事件级即时评估 + 文件内容嗅探
            （明文密码 / 私钥 / token 模式），🚨 实时打印并落盘
            <trace>_alerts.ndjson——进程被杀告警也在磁盘上。
  长期运行  逐事件实时落盘（原有）+ --resume 断点续写（哈希链无缝接续）
            + STOP 哨兵文件 + SIGTERM 优雅退出（退出码 42 = 正常停止，
            watchdog 据此不再拉起）+ 30 秒心跳事件（监视空窗可检测）。

事件复用 schema 0.1（SHA-256 哈希链防篡改），span 树：
  kiro.session（root）
  ├─ 进程 span（每 pid 一个）── net.connect / process.spawn / process.exit
  └─ workspace span ── fs.create / fs.write / fs.delete

用法：
  python3 kiro/observer.py --workspace /path/to/project [--duration 600]
  python3 kiro/observer.py --workspace ... --resume <trace_id>   # 断点续写
  python3 kiro/observer.py --workspace ... --seed-pid <pid>      # 监视任意 Agent
  优雅停止：touch events/STOP 或 kill -TERM <pid>（watchdog 配合）
"""
import argparse
import ctypes
import ctypes.util
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "runtime"))
sys.path.insert(0, os.path.join(ROOT, "correlator"))
from trace import EventWriter, new_id, redact, truncate  # noqa: E402
import rules as rules_mod  # noqa: E402  R1/R2/R3 复用同一套规则语义

KIRO_APP_PREFIX = "/Applications/Kiro.app"
DEFAULT_EXCLUDE = {"node_modules", ".venv", "__pycache__", ".next", "dist",
                   "build", ".turbo", ".DS_Store", "target", "vendor"}
GRACEFUL_EXIT_CODE = 42          # watchdog 约定：42 = 优雅停止，不重启

# ------------------------------------------------ 文件内容密钥嗅探（实时 R1）
SECRET_CONTENT_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("sshpass-password", re.compile(r"(?i)\bsshpass\b[^|;&]*\s-p\s+\S+")),
    ("password-assign", re.compile(
        r"(?i)\b(passw(or)?d|pwd|secret|token|api[_-]?key|server_pass)\b"
        r"\s*[=:]\s*['\"]?[^\s'\"]{8,}")),
]
SNIFF_MAX_BYTES = 262144         # 只嗅探 ≤256KB 的文件
SNIFF_SUFFIXES = {".sh", ".py", ".env", ".yml", ".yaml", ".json", ".txt",
                  ".md", ".conf", ".toml", ".ini", ".cfg", ".js", ".ts",
                  ".go", ".rb", ""}


# ---------------------------------------------------------------- 进程快照
def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def ps_snapshot():
    """返回 ({pid: {"ppid": int|None, "argv": str}}, 模式名)。

    优先 ps；沙箱等 ps 被禁的环境降级 libproc（proc_listallpids +
    proc_pidpath 拿 exe + PROC_PIDTBSDINFO 拿 ppid + KERN_PROCARGS2 拿 argv）。
    v2：libproc 降级模式也尽量拿 ppid，孙进程追踪不再因降级而失效。
    """
    try:
        r = subprocess.run(["ps", "-axo", "pid=,ppid=,args="],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            procs = {}
            for line in r.stdout.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    try:
                        procs[int(parts[0])] = {"ppid": int(parts[1]),
                                                "argv": parts[2]}
                    except ValueError:
                        pass
            if procs:
                return procs, "ps"
    except Exception:
        pass
    # 降级：libproc（自包含 ppid 获取）
    libc = _libc()
    count = libc.proc_listallpids(None, 0)
    if count <= 0:
        return {}, "libproc"
    pids = (ctypes.c_int32 * count)()
    n = libc.proc_listallpids(pids, ctypes.sizeof(pids))
    procs = {}
    pathbuf = ctypes.create_string_buffer(4096)
    for i in range(n):
        pid = pids[i]
        if libc.proc_pidpath(pid, pathbuf, 4096) <= 0:
            continue
        exe = pathbuf.value.decode("utf-8", "replace")
        # ppid via PROC_PIDTBSDINFO(3)：struct proc_bsdinfo 第 16 字节起是 pbi_ppid
        info = (ctypes.c_char * 128)()
        if libc.proc_pidinfo(pid, 3, 0, info, 128) > 0:
            ppid = int.from_bytes(info[16:20], "little", signed=True)
        else:
            ppid = None
        # argv via sysctl KERN_PROCARGS2（按 argc 截断，避免带出环境变量）
        argv = exe
        try:
            mib = (ctypes.c_int * 3)(1, 49, pid)
            size = ctypes.c_size_t(0)
            if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) == 0 \
                    and 0 < size.value < 1 << 20:
                b = ctypes.create_string_buffer(size.value)
                if libc.sysctl(mib, 3, b, ctypes.byref(size), None, 0) == 0:
                    argc = int.from_bytes(b.raw[:4], "little", signed=True)
                    if 0 < argc < 4096:
                        parts = b.raw[4:].split(b"\x00")
                        cand = [p.decode("utf-8", "replace")
                                for p in parts[:argc] if p]
                        if cand:
                            argv = " ".join(cand)
        except Exception:
            pass
        procs[pid] = {"ppid": ppid, "argv": argv}
    return procs, "libproc"


def build_tree(procs, seed_pids, extra_prefixes=()):
    """种子进程 + ppid 可达的全部子孙（Kiro 终端里的 shell/go/git/ssh…）。"""
    tree = set(seed_pids)
    children = {}
    for pid, d in procs.items():
        pp = d.get("ppid")
        if pp is not None:
            children.setdefault(pp, []).append(pid)
    queue = list(seed_pids)
    while queue:
        cur = queue.pop()
        for c in children.get(cur, []):
            if c not in tree:
                tree.add(c)
                queue.append(c)
    # 孤儿兜底：exe/argv 路径命中额外前缀（如 workspace 里编译出的二进制，
    # 中间父进程已退出导致 ppid 链断裂时仍可追踪）
    for pid, d in procs.items():
        if pid in tree:
            continue
        a = d.get("argv") or ""
        for pfx in extra_prefixes:
            if pfx and a.startswith(pfx):
                tree.add(pid)
                break
    return tree


# ---------------------------------------------------------------- 网络快照
def lsof_snapshot():
    """[(pid, local, peer_host, peer_port, kind)]，kind ∈ {connect, listen}。"""
    try:
        r = subprocess.run(["lsof", "-iTCP", "-n", "-P", "-F", "pn"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0 and not r.stdout.strip():
            return []
        out = r.stdout
    except Exception:
        return []
    conns, cur_pid = [], None
    for line in out.splitlines():
        if line.startswith("p"):
            try:
                cur_pid = int(line[1:])
            except ValueError:
                cur_pid = None
        elif line.startswith("n") and cur_pid is not None:
            name = line[1:]
            if "->" in name:
                local, peer = name.split("->", 1)
                ph, _, pp = peer.rpartition(":")
                conns.append((cur_pid, local, ph, pp, "connect"))
            else:
                conns.append((cur_pid, name, None, None, "listen"))
    return conns


def peer_kind(peer_host):
    if peer_host in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"):
        return "local"
    return "direct"


# ---------------------------------------------------------------- 文件监控
def scan_files(ws, exclude):
    state = {}
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            try:
                st = os.stat(full)
                state[os.path.relpath(full, ws)] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
    return state


def sniff_secrets(abs_path):
    """读取小文本文件，返回命中的密钥模式名列表（不外泄内容本身）。"""
    hits = []
    try:
        st = os.stat(abs_path)
        if st.st_size <= 0 or st.st_size > SNIFF_MAX_BYTES:
            return hits
        if os.path.splitext(abs_path)[1].lower() not in SNIFF_SUFFIXES:
            return hits
        with open(abs_path, "rb") as f:
            data = f.read()
        text = data.decode("utf-8", "replace")
        for name, pat in SECRET_CONTENT_PATTERNS:
            m = pat.search(text)
            if m:
                line_no = text[:m.start()].count("\n") + 1
                hits.append((name, line_no))
    except OSError:
        pass
    return hits


# ---------------------------------------------------------------- 实时告警
class RealtimeAlerts:
    """事件级即时规则评估：R1/R2/R3 + 内容嗅探，实时打印 + 落盘。"""

    def __init__(self, workspace, events_dir, trace_id):
        self.workspace = workspace
        self.ctx = {"workspace_root": workspace,
                    "net_allowlist": ["127.0.0.1", "::1", "localhost"]}
        self.path = os.path.join(events_dir, f"{trace_id}_alerts.ndjson")
        self.count = 0
        self._fh = open(self.path, "a", encoding="utf-8")

    def check(self, ev):
        alerts = rules_mod.evaluate([ev], self.ctx)
        # 内容嗅探（R1 增强）：fs.create/fs.write 命中密钥模式
        if ev.get("event_type") in ("fs.create", "fs.write"):
            rel = (ev.get("action", {}).get("arguments_redacted") or {}) \
                .get("path", "")
            if rel:
                hits = sniff_secrets(os.path.join(self.workspace, rel))
                for name, line_no in hits:
                    alerts.append({
                        "rule_id": "R1", "rule_name": "密钥访问",
                        "severity": "high", "span_id": ev.get("span_id"),
                        "parent_span_id": ev.get("parent_span_id"),
                        "trace_id": ev.get("trace_id"),
                        "timestamp": ev.get("timestamp"),
                        "event_type": ev.get("event_type"),
                        "source": ev.get("source"),
                        "detail": f"文件内容含疑似密钥（模式 {name}，"
                                  f"第 {line_no} 行）— {rel}",
                    })
        for a in alerts:
            self.count += 1
            self._fh.write(json.dumps(a, ensure_ascii=False) + "\n")
            self._fh.flush()
            print(f"\033[31m🚨 [{a['rule_id']}] {a['detail']}\033[0m",
                  flush=True)
        return alerts

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 观察器
class KiroObserver:
    def __init__(self, workspace, events_dir, poll_proc, poll_net, poll_file,
                 seed_pid=None, seed_pattern=None, resume=None, agent_name="Kiro",
                 collector_url=None, capture_reads=False):
        self.workspace = os.path.realpath(os.path.expanduser(workspace))
        self.poll_proc, self.poll_net, self.poll_file = poll_proc, poll_net, poll_file
        self.seed_pid = seed_pid
        self.seed_pattern = seed_pattern or KIRO_APP_PREFIX
        self.agent_name = agent_name
        self.collector_url = collector_url
        self.capture_reads = capture_reads
        self.stop_file = os.path.join(events_dir, "STOP")
        # 断点续写：沿用旧 trace_id + 从最后一事件恢复哈希链
        if resume:
            self.trace_id = resume
            self.writer = EventWriter(events_dir, resume)
            self._restore_chain(events_dir)
        else:
            self.trace_id = new_id("kiro")
            self.writer = EventWriter(events_dir, self.trace_id)
        self.alerts = RealtimeAlerts(self.workspace, events_dir, self.trace_id)
        self.session_span = new_id("span")
        self.ws_span = new_id("span")
        self.pid_spans = {}
        self.seen_pids = {}
        self.seen_conns = set()
        self.current_tree = set()      # 当轮实时进程树（网络归属用）
        self.file_baseline = None
        self.counts = {}
        self.start_time = time.time()
        self.resumed = bool(resume)
        self._stop_requested = False
        self.seen_fds = set()          # (pid,path) 已上报的文件读取，去重


    def _restore_chain(self, events_dir):
        path = os.path.join(events_dir, f"{self.trace_id}.ndjson")
        last = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line)
                        except json.JSONDecodeError:
                            continue
        if last:
            self.writer.prev_hash = last.get("evidence", {}).get("hash", "GENESIS")
            self.writer.count = sum(1 for _ in open(path, encoding="utf-8"))

    # ---- 事件发射（含实时告警 + collector 广播） ----
    def emit(self, span, parent, etype, actor, action):
        ev = self.writer.build(
            source="kiro_observer", event_type=etype,
            span_id=span, parent_span_id=parent,
            actor=actor, action=redact(action),
            policy={"decision": "observe",
                    "reason": "passive: 目标 Agent 不经过网关，仅系统事实观测"})
        self.writer.emit(ev)
        self.counts[etype] = self.counts.get(etype, 0) + 1
        self.alerts.check(ev)          # 实时告警：进程死了告警也在磁盘
        self._post_collector(ev)
        return ev

    def _post_collector(self, ev):
        if not self.collector_url:
            return
        try:
            data = json.dumps(ev, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                self.collector_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            # 网络抖动不致命，静默降级
            pass

    def proc_span(self, pid, argv):
        if pid not in self.pid_spans:
            sp = new_id("span")
            self.pid_spans[pid] = sp
            self.emit(sp, self.session_span, "process.span",
                      {"type": "process", "name": self._proc_name(argv, pid),
                       "pid": pid},
                      {"name": "process",
                       "arguments_redacted": {"pid": pid, "exe": argv},
                       "result_summary": {}})
        return self.pid_spans[pid]

    @staticmethod
    def _proc_name(argv, pid):
        if not argv:
            return f"pid{pid}"
        return argv.split(" ")[0].split("/")[-1]

    def _seed_pids(self, procs):
        seeds = [p for p, d in procs.items()
                 if (d.get("argv") or "").startswith(self.seed_pattern)]
        if self.seed_pid and self.seed_pid in procs:
            seeds.append(self.seed_pid)
        return set(seeds)

    # ---- 三层采集 ----
    def poll_processes(self):
        procs, mode = ps_snapshot()
        seeds = self._seed_pids(procs)
        tree = build_tree(procs, seeds,
                          extra_prefixes=(self.workspace + "/",))
        self.current_tree = tree
        if not self.seen_pids and tree:
            # 首轮（或续写重启首轮）：当前树作为基线静默入账
            for pid in sorted(tree):
                self.seen_pids[pid] = procs[pid].get("argv") or ""
                self.proc_span(pid, self.seen_pids[pid])
            self._print(f"  进程基线：{len(tree)} 个（模式 {mode}）")
            return
        for pid in sorted(tree):
            if pid not in self.seen_pids:
                argv = procs[pid].get("argv") or ""
                self.seen_pids[pid] = argv
                parent_pid = procs[pid].get("ppid")
                parent_span = (self.pid_spans.get(parent_pid) or
                               self.session_span)
                self.emit(new_id("span"), parent_span, "process.spawn",
                          {"type": "process", "name": self._proc_name(argv, pid),
                           "pid": pid},
                          {"name": "spawn",
                           "arguments_redacted": {"pid": pid,
                                                  "ppid": parent_pid,
                                                  "argv": truncate(argv, 400),
                                                  "scan_mode": mode},
                           "result_summary": {"tree_size": len(tree)}})
                self._print(f"🌱 process.spawn pid{pid} "
                            f"{self._proc_name(argv, pid)}  {truncate(argv, 90)}")
                self.proc_span(pid, argv)
        for pid in list(self.seen_pids):
            if pid not in tree:
                argv = self.seen_pids.pop(pid)
                sp = self.pid_spans.get(pid, self.session_span)
                self.emit(sp, self.session_span, "process.exit",
                          {"type": "process", "pid": pid},
                          {"name": "exit",
                           "arguments_redacted": {"pid": pid},
                           "result_summary": {"argv": truncate(argv, 200)}})

    def poll_network(self):
        # 关键修复：按"当轮实时树 ∪ 已见 pid"归属，短命孙进程连接不再漏
        allowed = self.current_tree | set(self.seen_pids)
        for pid, local, ph, pp, kind in lsof_snapshot():
            if pid not in allowed:
                continue
            key = (pid, local, ph, pp, kind)
            if key in self.seen_conns:
                continue
            self.seen_conns.add(key)
            span = self.pid_spans.get(pid) or self.proc_span(
                pid, self.seen_pids.get(pid, ""))
            if kind == "listen":
                self.emit(span, self.session_span, "net.listen",
                          {"type": "process", "pid": pid},
                          {"name": "listen",
                           "arguments_redacted": {"local": local},
                           "result_summary": {}})
                self._print(f"🔌 net.listen    pid{pid} {local}")
                continue
            pk = peer_kind(ph)
            note = "本地回环(代理/内部服务)" if pk == "local" else "⚠️ 直连公网(绕过代理)"
            self.emit(span, self.session_span, "net.connect",
                      {"type": "process", "pid": pid},
                      {"name": "connect",
                       "arguments_redacted": {"local": local,
                                              "peer": f"{ph}:{pp}",
                                              "peer_kind": pk},
                       "result_summary": {"note": note}})
            self._print(f"🌐 net.connect   pid{pid} {local} → {ph}:{pp}  [{note}]")

    def poll_files(self):
        if self.capture_reads:
            self._poll_file_reads()
        cur = scan_files(self.workspace, DEFAULT_EXCLUDE)
        if self.file_baseline is None:
            self.file_baseline = cur
            if self.resumed:
                # 续写重启：diff 出停止期间的文件变化并补记
                pass  # 基线即当前态，变化从现在起记录
            return
        base = self.file_baseline
        for rel, st in cur.items():
            if rel not in base:
                etype, icon, verb = "fs.create", "🆕", "创建"
            elif base[rel] != st:
                etype, icon, verb = "fs.write", "✍️", "修改"
            else:
                continue
            self.emit(self.ws_span, self.session_span, etype,
                      {"type": "workspace", "path": rel},
                      {"name": verb,
                       "arguments_redacted": {"path": rel},
                       "result_summary": {"size": st[1]}})
            self._print(f"{icon} {etype:<11} {rel}  ({st[1]}B)")
        for rel in base:
            if rel not in cur:
                self.emit(self.ws_span, self.session_span, "fs.delete",
                          {"type": "workspace", "path": rel},
                          {"name": "删除",
                           "arguments_redacted": {"path": rel},
                           "result_summary": {}})
                self._print(f"🗑️ fs.delete     {rel}")
        self.file_baseline = cur

    # ---------------------------------------------------------------- 文件读取捕获
    SENSITIVE_READ_PATTERNS = [
        ".ssh/", ".gnupg/", ".aws/", ".gitconfig", ".git-credentials",
        ".netrc", "Keychains", ".npmrc", ".pypirc", ".docker/config.json",
        ".kube/config", ".env", ".bash_history", ".zsh_history",
        ".bashrc", ".zshrc", ".profile", ".zprofile", ".bash_profile",
        ".claude.json", ".git-credentials", ".dockerignore", ".p10k.zsh",
    ]

    def _is_sensitive_read(self, path):
        """判定一个已打开文件路径是否值得上报为 fs.read。

        只报已知敏感模式，避免把 .DS_Store 等噪音全报上来。
        """
        p = path.lower()
        for pat in self.SENSITIVE_READ_PATTERNS:
            if pat.lower() in p:
                return True
        return False

    def _poll_file_reads(self):
        """通过 lsof 文件描述符扫描捕获进程打开的文件（重点：敏感读取）。"""
        for pid in self.current_tree:
            try:
                r = subprocess.run(["lsof", "-a", "-p", str(pid), "-F", "fn"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    continue
                cur_fd = None
                for line in r.stdout.splitlines():
                    if line.startswith("f"):
                        cur_fd = line[1:]
                    elif line.startswith("n") and cur_fd:
                        path = line[1:]
                        key = (pid, path)
                        if key in self.seen_fds:
                            cur_fd = None
                            continue
                        # lsof FD 列：cwd/txt/rtd/mem 等表示打开；'r' 读模式，'u' 读写
                        # 这里只要有路径即认为已打开，再做敏感过滤避免噪音
                        if self._is_sensitive_read(path):
                            self.seen_fds.add(key)
                            span = self.pid_spans.get(pid) or self.proc_span(
                                pid, self.seen_pids.get(pid, ""))
                            self.emit(span, self.session_span, "fs.read",
                                      {"type": "process", "pid": pid},
                                      {"name": "read",
                                       "arguments_redacted": {
                                           "path": path,
                                           "fd": cur_fd,
                                           "sensitive": True},
                                       "result_summary": {}})
                            self._print(f"📖 fs.read       pid{pid} {path}")
                        cur_fd = None
            except Exception:
                pass

    def heartbeat(self):
        self.emit(self.session_span, None, "session.heartbeat",
                  {"type": "agent", "name": self.agent_name},
                  {"name": "heartbeat",
                   "arguments_redacted": {},
                   "result_summary": {
                       "uptime_sec": round(time.time() - self.start_time, 0),
                       "events": self.writer.count,
                       "realtime_alerts": self.alerts.count,
                       "tree_size": len(self.current_tree)}})

    def _print(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    # ---- 主循环 ----
    def run(self, duration):
        procs, mode = ps_snapshot()
        seeds = self._seed_pids(procs)
        begin_type = "trace.resume" if self.resumed else "trace.begin"
        self.emit(self.session_span, None, begin_type,
                  {"type": "agent", "name": self.agent_name, "vendor": "AWS",
                   "mode": "passive-observer-v2"},
                  {"name": "session",
                   "arguments_redacted": {
                       "workspace_root": self.workspace,
                       "net_allowlist": ["127.0.0.1", "::1", "localhost"],
                       "seed_processes_at_start": len(seeds),
                       "proc_scan_mode": mode,
                       "note": "被动观察 v2：全进程树追踪（含孙进程）+ "
                               "实时告警 + 断点续写"},
                   "result_summary": {}})
        self._print(f"◆ {begin_type}  workspace={self.workspace}")
        self._print(f"  种子进程: {len(seeds)} 个，扫描模式: {mode}")
        self._print(f"  优雅停止: touch {self.stop_file} 或 kill -TERM；"
                    f"实时告警实时落盘")

        signal.signal(signal.SIGTERM, self._request_stop)
        t_proc = t_net = t_file = t_hb = time.time()
        try:
            while not self._stop_requested:
                now = time.time()
                if now - t_proc >= self.poll_proc:
                    self.poll_processes(); t_proc = now
                if now - t_net >= self.poll_net:
                    self.poll_network(); t_net = now
                if now - t_file >= self.poll_file:
                    self.poll_files(); t_file = now
                if now - t_hb >= 30:
                    self.heartbeat(); t_hb = now
                if os.path.exists(self.stop_file):
                    try:
                        os.remove(self.stop_file)
                    except OSError:
                        pass
                    self._print("  收到 STOP 哨兵，优雅停止")
                    break
                if duration and now - self.start_time >= duration:
                    break
                time.sleep(0.15)
        except KeyboardInterrupt:
            pass

        self.emit(self.session_span, None, "trace.end",
                  {"type": "agent", "name": self.agent_name},
                  {"name": "session_end",
                   "arguments_redacted": {},
                   "result_summary": {"duration_sec": round(time.time() - self.start_time, 1),
                                      "events": self.writer.count,
                                      "realtime_alerts": self.alerts.count,
                                      "by_type": self.counts}})
        self.alerts.close()
        return self.finish()

    def _request_stop(self, signum, frame):
        self._stop_requested = True

    def finish(self):
        events_path = self.writer.path
        out_dir = os.path.join(ROOT, "output", self.trace_id)
        os.makedirs(out_dir, exist_ok=True)
        self._print(f"\n◆ trace.end      共 {self.writer.count} 条事件 → {events_path}")
        import shutil
        processed = os.path.join(out_dir, "processed.ndjson")
        shutil.copyfile(events_path, processed)
        # 实时告警也归档一份
        if self.alerts.count:
            shutil.copyfile(self.alerts.path,
                            os.path.join(out_dir, "realtime_alerts.ndjson"))
        try:
            subprocess.run([sys.executable,
                            os.path.join(ROOT, "correlator", "correlate.py"),
                            "--input", processed, "--out", out_dir],
                           check=True)
        except Exception as e:
            print(f"correlate 失败: {e}", file=sys.stderr)
        print(f"\n报告目录: {out_dir}")
        print(f"  timeline.md / alerts.json / trace_summary.json / evidence_pkg/")
        return out_dir


def main():
    ap = argparse.ArgumentParser(
        description="被动观察器 v2（全进程树 + 实时告警 + 断点续写）")
    ap.add_argument("--workspace", required=True, help="Agent 打开的项目路径")
    ap.add_argument("--duration", type=int, default=0,
                    help="监视秒数（0 = 一直运行到 STOP/TERM）")
    ap.add_argument("--events-dir", default=os.path.join(ROOT, "events"))
    ap.add_argument("--poll-proc", type=float, default=0.5,
                    help="进程轮询间隔秒（v2 默认 0.5，孙进程不漏拍）")
    ap.add_argument("--poll-net", type=float, default=0.3,
                    help="网络轮询间隔秒（v2 默认 0.3）")
    ap.add_argument("--poll-file", type=float, default=3.0)
    ap.add_argument("--seed-pid", type=int, default=None,
                    help="种子进程 pid（监视任意 Agent，不必是 Kiro）")
    ap.add_argument("--seed-pattern", default=KIRO_APP_PREFIX,
                    help="种子进程 argv 前缀（默认 /Applications/Kiro.app）")
    ap.add_argument("--agent-name", default="Kiro")
    ap.add_argument("--resume", default=None,
                    help="续写的 trace_id：沿用哈希链继续记录同一会话")
    ap.add_argument("--collector", default=None,
                    help="实时面板收集器 URL，例如 http://127.0.0.1:8787/ingest")
    ap.add_argument("--capture-reads", action="store_true",
                    help="启用 lsof 文件描述符扫描，捕获敏感文件读取（fs.read）")
    args = ap.parse_args()

    if not os.path.isdir(args.workspace):
        print(f"workspace 不存在: {args.workspace}", file=sys.stderr)
        sys.exit(1)

    obs = KiroObserver(args.workspace, args.events_dir,
                       args.poll_proc, args.poll_net, args.poll_file,
                       seed_pid=args.seed_pid,
                       seed_pattern=args.seed_pattern,
                       resume=args.resume, agent_name=args.agent_name,
                       collector_url=args.collector,
                       capture_reads=args.capture_reads)
    obs.run(args.duration or None)
    sys.exit(GRACEFUL_EXIT_CODE if obs._stop_requested else 0)


if __name__ == "__main__":
    main()
