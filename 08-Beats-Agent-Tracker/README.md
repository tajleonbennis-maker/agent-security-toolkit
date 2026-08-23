# Beats Agent Tracker

以 **Elastic Beats 作为纯采集层** 的 Agent 执行跟踪器：把一次 Agent 任务的全过程
（模型轮次 → 工具调用 → 子进程 → 文件读写 → 网络连接）按统一 Trace 模型关联起来，
形成可重放、可取证、防篡改的执行链证据。

对应规范：[07-Agent-Execution-Trace-Observability.md](https://github.com/tajleonbennis-maker/agent-security-toolkit/blob/main/07-Agent-Execution-Trace-Observability.md)

## 设计原则：Beats 专注于采集

```text
┌────────────────────────── 采集域（Beats 只做这些） ──────────────────────────┐
│                                                                              │
│  Agent Runtime ──事件──▶ events/*.ndjson ──▶ Filebeat                        │
│  Tool Gateway ───事件──▶                    │  decode_json_fields           │
│  Process Sensor ─事件──▶                    │  脱敏 processor（密钥/令牌）   │
│  Net Sensor ─────事件──▶                    │  trace_id→trace.id ECS 映射    │
│                                             │  fingerprint 指纹              │
│                                             ▼                               │
│                                    console / file / Elasticsearch            │
│  内核/驱动层 ─────流量──▶ Packetbeat（flow/DNS/HTTP，无 trace_id）            │
│                                             │                                │
│                                             ▼                                │
│                     correlator/enrich.py：四元组+时间窗 join 回 trace         │
└──────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────── 关联域（本项目的 correlator） ─────────────────────┐
│  Span 树重建 · 时间轴 · PID/时间窗关联 · 3 条风险规则 · 证据包（哈希链）      │
└──────────────────────────────────────────────────────────────────────────────┘
```

**职责边界**（对应文档第 5 节的架构，把 OpenTelemetry Collector 换成 Beats）：

| 层 | 组件 | 本项目实现 |
|---|---|---|
| Runtime Adapter | 模型轮次/工具/审批 Trace | `runtime/agent.py` + `runtime/gateway.py` |
| Controlled Tool Gateway | shell/文件包装器 + 脱敏 | `runtime/gateway.py`（read_file/write_file/run_command） |
| 系统探针 | 进程详情 | `runtime/sensors.py` ProcessMonitor（`process.spawn`：pid/ppid/exe/argv；macOS libproc，Linux /proc，无 ps 依赖） |
| 系统探针 | TCP 连接 | `runtime/sensors.py` NetMonitor（lsof 四元组 → `net.connect`） |
| 采集与传输 | Collector（事件流） | **Filebeat**（`beats/filebeat.yml`） |
| 采集与传输 | Collector（流量流） | **Packetbeat**（`beats/packetbeat.yml`，flow/DNS/HTTP，需 root） |
| Trace Store | 存储 | 本地 NDJSON（MVP）/ Elasticsearch（docker-compose） |
| 关联与重放 | Timeline / Graph / Replay | `correlator/` |
| 流量关联 | 无 trace_id 的流量 → trace | `correlator/enrich.py`（四元组+时间窗 join；join 不上的标记 `unattributed`＝绕过网关出网的信号） |

## 统一事件格式（schema 0.1）

每个事件一行 NDJSON，与文档 3.1 节完全一致：

```json
{
  "schema_version": "0.1",
  "trace_id": "trace_01J...",
  "span_id": "span_01J...",
  "parent_span_id": null,
  "timestamp": "2026-08-22T20:00:00+08:00",
  "source": "agent_runtime",
  "event_type": "model.turn",
  "actor": {"agent": "...", "model": "...", "principal": "..."},
  "action": {"name": "...", "arguments_redacted": {...}, "result_summary": {...}},
  "policy": {"decision": "allow", "rule_id": "...", "approval_id": null},
  "evidence": {"artifact_hashes": [], "raw_event_ref": "object://events/..."}
}
```

## 快速开始（无需 Elasticsearch）

```bash
# 1. 运行演示 Agent 任务（含植入的间接提示注入测试指令）
python3 runtime/agent.py --task tasks/demo_task.json --workspace /tmp/agent-ws

# 2. Filebeat 采集 + 脱敏 + ECS 映射（Beats 专注采集层）
filebeat -c beats/filebeat.yml   # 读取 events/*.ndjson → output/processed.ndjson

# 3. 关联引擎：重建执行链 + 风险规则 + 证据包
python3 correlator/correlate.py --input output/processed.ndjson --out output/

# 4.（可选）流量采集与关联 —— Packetbeat 需 root
sudo packetbeat -c beats/packetbeat.yml   # → output/packetbeat.ndjson
python3 correlator/enrich.py output/processed.ndjson output/packetbeat.ndjson \
  output/traffic.enriched.ndjson          # 流量 join 回 trace（join 不上的=可疑）
```

或一键：`bash demo/run_demo.sh`；开启实时流量采集：`sudo RUN_PACKETBEAT=1 bash demo/run_demo.sh`（macOS 需按 `beats/packetbeat.yml` 注释调整抓包网卡）。

## 完整栈（Elasticsearch + Kibana）

```bash
docker compose up -d   # ES + Kibana + Filebeat（对接 ingest pipeline）
```

Kibana 中按 `trace.id` 过滤即可看到一次任务的完整执行链。

## 检测规则（MVP 内置三条）

| 规则 | 事件 | 判定 |
|---|---|---|
| R1 密钥访问 | `fs.read` | 路径命中密钥/金丝雀文件清单（`.env`、`id_rsa`、canary 等） |
| R2 越界写入 | `fs.write` | 写入路径逃逸出 workspace 根目录 |
| R3 异常外联 | `net.connect` | 目标主机不在白名单，或单连接流量超阈值 |

## 证据完整性

- 每个事件写入时计算 SHA-256，并纳入**哈希链**（`evidence.prev_hash`）
- 证据包导出后可用 `python3 correlator/evidence.py verify <pkg>` 验证未被篡改
- 原始证据（raw stdout/stderr）与展示字段分离；默认脱敏 Authorization/Cookie/API Key/私钥

## 目录结构

```
runtime/     Agent 模拟运行时 + 工具网关 + 传感器（事件发射层）
tasks/       演示任务定义（JSON，可插拔到真实 LLM Runtime）
beats/       Filebeat/Packetbeat 配置 + ES ingest pipeline（采集层）
correlator/  Span 树重建、时间轴、规则引擎、流量关联、证据包（关联层）
demo/        端到端演示脚本
docs/        架构文档
```

## 研究伦理

仅用于自有或书面授权的 Agent/账号/网络/基础设施上的安全研究；演示任务使用
无害测试指令与自控接收端，不使用真实秘密。
