#!/usr/bin/env python3
"""
mitmproxy addon：把 Kiro / 其他 Agent 的 HTTPS 流量翻译成 schema 0.1 事件

捕获：
- tool.http_request / tool.http_response：JSON API 调用（含工具名、参数、结果）
- net.connect：TCP 连接的 richer 数据（SNI、HTTP Host、JA3 指纹、对端域名）
- llm.request / llm.response：向大模型 API 发送的 chat/completions 类请求

启动方式（需先安装 mitmproxy CA）：
  mitmproxy --mode regular@8080 --scripts dashboard/mitm_addon.py
或透明代理（需 pf）：
  mitmproxy --mode transparent --scripts dashboard/mitm_addon.py

环境变量：
  COLLECTOR_URL=http://127.0.0.1:8787/ingest
  TRACE_ID=kiro_live
"""
import json
import os
import re
import secrets
import sys
import time
import urllib.request
from urllib.parse import urlsplit

# mitmproxy 二进制自带 mitm 命名空间；在独立 python 中运行 addon 时由 mitmproxy 注入
from mitmproxy import http, ctx

COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:8787/ingest")
TRACE_ID = os.environ.get("TRACE_ID", "kiro_live")
SPAN_COUNTER = [0]


def _span_id():
    SPAN_COUNTER[0] += 1
    return f"http_{SPAN_COUNTER[0]:06d}_{secrets.token_hex(4)}"


def _post(event: dict):
    """POST 到 collector；失败静默。"""
    try:
        data = json.dumps(event, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            COLLECTOR_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        ctx.log.debug(f"[mitm_addon] post failed: {e}")


def _make_event(event_type: str, span_id: str, parent_span_id: str,
                actor: dict, action: dict, extra: dict = None) -> dict:
    return {
        "schema_version": "0.1",
        "trace_id": TRACE_ID,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{time.time_ns()%1_000_000_000:09d}"[:3] + "Z",
        "event_type": event_type,
        "source": "mitmproxy",
        "actor": actor,
        "action": action,
        "evidence": {"integrity": "sha256-chain"},
        **(extra or {}),
    }


def _host_from_flow(flow: http.HTTPFlow) -> str:
    host = flow.request.pretty_host or flow.request.host
    if not host or host == flow.request.host:
        sni = getattr(flow.server_conn, "sni", None)
        if sni:
            host = sni
    return host


def _looks_like_tool_call(req_json, resp_json, url: str) -> dict:
    """启发式识别工具调用。返回 {'tool_name': ..., 'arguments': ...} 或 None。"""
    text = json.dumps(req_json) + "\n" + json.dumps(resp_json)
    # Kiro 可能使用的工具名关键字
    tool_names = ["webFetch", "remote_web_search", "web_search", "fetch", "execute_command",
                  "run_command", "read_file", "write_file", "edit_file", "bash", "python"]
    for name in tool_names:
        if name in text:
            return {"tool_name": name, "arguments": req_json}
    # OpenAI function call 格式
    if isinstance(req_json, dict):
        if "functions" in req_json or "tools" in req_json:
            return {"tool_name": "llm_tools", "arguments": req_json}
    return None


def _looks_like_llm(url: str, req_json, resp_json) -> bool:
    return any(k in url for k in ["chat/completions", "messages", "anthropic", "bedrock", "claude"])


def _extract_messages(req_json, resp_json):
    """从 OpenAI / Anthropic 请求/响应中提取对话消息。"""
    msgs = []
    if isinstance(req_json, dict):
        for m in req_json.get("messages", []):
            if isinstance(m, dict) and "role" in m:
                msgs.append({"direction": "user", "role": m["role"],
                             "content": str(m.get("content", ""))[:2000]})
        # Anthropic
        for m in req_json.get("prompt", "") or []:
            if isinstance(m, dict):
                msgs.append({"direction": "user", "role": m.get("role", "user"),
                             "content": str(m.get("content", ""))[:2000]})
    if isinstance(resp_json, dict):
        # OpenAI
        for c in resp_json.get("choices", []):
            m = c.get("message", {})
            if m:
                msgs.append({"direction": "assistant", "role": m.get("role", "assistant"),
                             "content": str(m.get("content", ""))[:2000]})
        # Anthropic
        if "completion" in resp_json:
            msgs.append({"direction": "assistant", "role": "assistant",
                         "content": str(resp_json["completion"])[:2000]})
        if "content" in resp_json:
            msgs.append({"direction": "assistant", "role": "assistant",
                         "content": str(resp_json["content"])[:2000]})
    return msgs


class AgentTrafficAddon:
    def __init__(self):
        self.flow_spans = {}  # flow.id -> span_id

    def request(self, flow: http.HTTPFlow):
        span_id = _span_id()
        self.flow_spans[flow.id] = span_id
        host = _host_from_flow(flow)

        # 1.  richer net.connect
        peer = f"{flow.server_conn.peername[0]}:{flow.server_conn.peername[1]}" if flow.server_conn.peername else None
        net_ev = _make_event(
            "net.connect",
            span_id,
            None,
            actor={"type": "process", "pid": None, "name": "Kiro", "path": "/Applications/Kiro.app"},
            action={
                "name": "http_request",
                "arguments_redacted": {
                    "method": flow.request.method,
                    "host": host,
                    "path": flow.request.path,
                    "url": flow.request.pretty_url,
                    "peer": peer,
                    "sni": getattr(flow.server_conn, "sni", None),
                    "ja3": getattr(flow.client_conn, "ja3", None),
                    "headers": dict(flow.request.headers),
                },
                "result_summary": {},
                "summary": f"{flow.request.method} {host}{flow.request.path}",
            },
        )
        _post(net_ev)

        # 2. 尝试解析请求体为 LLM / tool 调用
        req_json = None
        try:
            if flow.request.content:
                req_json = json.loads(flow.request.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        if req_json:
            tool = _looks_like_tool_call(req_json, {}, flow.request.pretty_url)
            if tool:
                tool_ev = _make_event(
                    "tool.invoke",
                    f"{span_id}_tool",
                    span_id,
                    actor={"type": "agent", "name": "Kiro"},
                    action={
                        "name": tool["tool_name"],
                        "arguments_redacted": tool["arguments"],
                        "result_summary": {},
                        "summary": f"调用工具 {tool['tool_name']}",
                    },
                )
                _post(tool_ev)

            if _looks_like_llm(flow.request.pretty_url, req_json, {}):
                llm_ev = _make_event(
                    "llm.request",
                    f"{span_id}_llm",
                    span_id,
                    actor={"type": "agent", "name": "Kiro"},
                    action={
                        "name": "chat_completion",
                        "arguments_redacted": req_json,
                        "result_summary": {},
                        "summary": f"LLM request to {host}",
                    },
                )
                _post(llm_ev)
                # 提取并广播用户最新一轮消息
                for m in _extract_messages(req_json, {}):
                    if m["role"] in ("user", "human"):
                        conv_ev = _make_event(
                            "conversation.user",
                            f"{span_id}_conv_user",
                            f"{span_id}_llm",
                            actor={"type": "user", "name": "operator"},
                            action={
                                "name": "user_message",
                                "arguments_redacted": {"role": m["role"], "preview": m["content"][:200]},
                                "result_summary": {},
                                "summary": f"User → Kiro: {m['content'][:120]}",
                            },
                        )
                        _post(conv_ev)

    def response(self, flow: http.HTTPFlow):
        span_id = self.flow_spans.pop(flow.id, _span_id())
        host = _host_from_flow(flow)

        resp_json = None
        try:
            if flow.response.content:
                resp_json = json.loads(flow.response.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        req_json = None
        try:
            if flow.request.content:
                req_json = json.loads(flow.request.content.decode("utf-8", errors="ignore"))
        except Exception:
            pass

        # tool.result / llm.response
        if req_json:
            tool = _looks_like_tool_call(req_json, resp_json, flow.request.pretty_url)
            if tool:
                tool_result_ev = _make_event(
                    "tool.result",
                    f"{span_id}_tool_result",
                    f"{span_id}_tool",
                    actor={"type": "agent", "name": "Kiro"},
                    action={
                        "name": tool["tool_name"],
                        "arguments_redacted": {"status_code": flow.response.status_code},
                        "result_summary": resp_json if isinstance(resp_json, dict) else {"body": str(resp_json)[:2000]},
                        "summary": f"工具 {tool['tool_name']} 返回 HTTP {flow.response.status_code}",
                    },
                )
                _post(tool_result_ev)

            if _looks_like_llm(flow.request.pretty_url, req_json, resp_json):
                llm_resp_ev = _make_event(
                    "llm.response",
                    f"{span_id}_llm_result",
                    f"{span_id}_llm",
                    actor={"type": "agent", "name": "Kiro"},
                    action={
                        "name": "chat_completion",
                        "arguments_redacted": {"status_code": flow.response.status_code},
                        "result_summary": resp_json if isinstance(resp_json, dict) else {"body": str(resp_json)[:2000]},
                        "summary": f"LLM response HTTP {flow.response.status_code}",
                    },
                )
                _post(llm_resp_ev)
                # 提取并广播 Kiro/模型回复
                for m in _extract_messages(req_json, resp_json):
                    if m["direction"] == "assistant":
                        conv_ev = _make_event(
                            "conversation.assistant",
                            f"{span_id}_conv_assistant",
                            f"{span_id}_llm",
                            actor={"type": "agent", "name": "Kiro"},
                            action={
                                "name": "assistant_message",
                                "arguments_redacted": {"role": m["role"], "preview": m["content"][:200]},
                                "result_summary": {},
                                "summary": f"Kiro → User: {m['content'][:120]}",
                            },
                        )
                        _post(conv_ev)

        # HTTP 响应摘要事件（便于面板展示）
        http_ev = _make_event(
            "tool.http",
            f"{span_id}_resp",
            span_id,
            actor={"type": "agent", "name": "Kiro"},
            action={
                "name": "http_response",
                "arguments_redacted": {
                    "method": flow.request.method,
                    "host": host,
                    "path": flow.request.path,
                    "status_code": flow.response.status_code,
                    "content_type": flow.response.headers.get("content-type", ""),
                },
                "result_summary": {},
                "summary": f"{flow.request.method} {host}{flow.request.path} -> {flow.response.status_code}",
            },
        )
        _post(http_ev)


addons = [AgentTrafficAddon()]
