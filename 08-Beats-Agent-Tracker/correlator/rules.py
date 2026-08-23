"""风险检测规则（规范第 7 节 MVP 第 7 条：内置三条规则）。

R1 密钥访问：fs.read 命中密钥/金丝雀文件清单
R2 越界写入：fs.write 逃逸出 workspace 根目录
R3 异常外联：net.connect 目标主机不在白名单
"""
import fnmatch
import os

SECRET_PATH_PATTERNS = [
    "**/.env", "**/.env.*", "**/id_rsa*", "**/.ssh/**", "**/.aws/credentials",
    "**/.agent-canary/**", "**/*secret*", "**/*credential*", "**/*.pem",
    "**/*.key", "**/canary*",
]


def _match_secret_path(path: str) -> str:
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    base = norm.split("/")[-1]
    segments = norm.split("/")
    for pat in SECRET_PATH_PATTERNS:
        # 目录型模式（**/.ssh/**）：路径中包含该目录段即命中
        if pat.endswith("/**"):
            seg = pat[:-3].split("/")[-1]
            if seg and seg in segments:
                return pat
            continue
        tail = pat.split("/")[-1]
        if fnmatch.fnmatch(base, tail) or fnmatch.fnmatch(norm, pat):
            return pat
    return None


def _resolve(path: str, workspace: str) -> str:
    if not os.path.isabs(path):
        return os.path.join(workspace, path)
    return path


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(root) + os.sep)
    except Exception:
        return False


def evaluate(events: list, context: dict) -> list:
    """context: {workspace_root, net_allowlist} 来自 trace.begin 事件。"""
    workspace = context.get("workspace_root") or "/NONEXISTENT"
    allowlist = set(context.get("net_allowlist") or [])
    alerts = []

    for ev in events:
        etype = ev.get("event_type")
        args = (ev.get("action") or {}).get("arguments_redacted") or {}

        if etype == "fs.read":
            path = args.get("path", "")
            pat = _match_secret_path(path)
            if pat:
                alerts.append(_alert("R1", "high", ev,
                    f"读取了疑似密钥/金丝雀文件 {path}（命中模式 {pat}）"))

        elif etype == "fs.write":
            path = _resolve(args.get("path", ""), workspace)
            if not _inside(path, workspace):
                alerts.append(_alert("R2", "high", ev,
                    f"写入越界：{args.get('path')} → {path} 不在工作区 {workspace} 内"))

        elif etype == "net.connect":
            peer = args.get("peer") or ""
            host = peer.rsplit(":", 1)[0] if peer else None
            state = args.get("state", "")
            if host and host not in allowlist and state in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
                alerts.append(_alert("R3", "high", ev,
                    f"异常外联：连接非白名单主机 {peer}（state={state}）"))

    return alerts


def _alert(rule_id, severity, ev, detail):
    return {
        "rule_id": rule_id,
        "rule_name": {"R1": "密钥访问", "R2": "越界写入", "R3": "异常外联"}[rule_id],
        "severity": severity,
        "span_id": ev.get("span_id"),
        "parent_span_id": ev.get("parent_span_id"),
        "trace_id": ev.get("trace_id"),
        "timestamp": ev.get("timestamp"),
        "event_type": ev.get("event_type"),
        "source": ev.get("source"),
        "detail": detail,
    }
