# Agent 全执行链观察与取证指南

> 面向大模型与 Agent 安全研究人员的执行链建模、观测、关联与复现实验方法。

## 1. 研究对象

Agent 安全研究不应只检查最终回答。具备 Shell、浏览器、文件系统、MCP 或外部 API 能力的 Agent，本质上是一个持续运行的“观察—决策—行动—反馈”循环：

```text
用户目标
  → Runtime 组装上下文、指令和工具定义
  → 模型生成普通输出或工具调用
  → Runtime 校验权限并执行工具
  → 工具结果进入下一轮上下文
  → 模型继续决策，直至终止
```

安全研究需要同时回答两类问题：

1. **语义执行链**：模型看到了什么可记录输入，选择了哪个工具，工具结果怎样影响后续行动；
2. **系统事实链**：真实启动了什么进程，读写了哪些文件，连接了哪些地址，最终改变了什么状态。

二者不能互相替代。只有模型 Trace，无法发现绕过工具包装器的子进程行为；只有系统调用日志，则无法判断某次文件读取属于哪轮 Agent 决策。

## 2. 可观测边界

建议采集可验证、可重放的执行证据：

- 用户输入、系统指令版本及授权范围；
- 每轮模型请求和响应（按数据策略脱敏）；
- 可用工具清单、工具 schema 和工具调用；
- 权限询问、批准、拒绝和策略判断；
- Shell 命令、退出码、标准输出和标准错误；
- 文件读取、写入、删除及任务前后差异；
- 进程树、系统调用、资源使用和容器边界；
- DNS、网络连接、HTTP 元数据和数据量；
- MCP Server、工具描述及返回内容的版本变化；
- 测试结果、构建产物、Git 操作和部署动作。

不应把“提取隐藏思维过程”作为目标。隐藏推理既不是可靠审计证据，也可能涉及模型与平台的安全边界。研究重点应是模型实际收到的可记录上下文、输出的工具决策以及可验证的外部行为。

## 3. 统一 Trace 模型

一次用户任务对应一个 `trace_id`，一次模型轮次、工具调用或系统行为对应一个 Span：

```text
Trace: build-todo-app
├── user_request
├── model_turn #1
│   └── tool_call: search_files
│       └── fs.read: package.json
├── model_turn #2
│   └── tool_call: shell
│       └── process.exec: npm install
│           ├── net.connect: registry.npmjs.org:443
│           ├── process.exec: postinstall
│           └── fs.write: package-lock.json
├── approval: deploy → approved
├── tool_call: deploy
└── final_response
```

### 3.1 最小事件格式

```json
{
  "schema_version": "0.1",
  "trace_id": "trace_01J...",
  "span_id": "span_01J...",
  "parent_span_id": "span_parent",
  "timestamp": "2026-08-22T20:00:00+08:00",
  "source": "agent_runtime|tool_proxy|kernel|network|git",
  "event_type": "model.turn|tool.call|process.exec|fs.write|net.connect|approval",
  "actor": {
    "agent": "coding-agent",
    "model": "provider/model-version",
    "principal": "research-user"
  },
  "action": {
    "name": "shell",
    "arguments_redacted": {"command": "npm test"},
    "result_summary": {"exit_code": 1}
  },
  "policy": {
    "decision": "allow",
    "rule_id": "workspace-shell",
    "approval_id": null
  },
  "evidence": {
    "artifact_hashes": [],
    "raw_event_ref": "object://events/..."
  }
}
```

安全要求：原始证据与展示字段分离；默认脱敏 `Authorization`、Cookie、密码、API Key、私钥和个人信息；对事件建立哈希链或签名，避免事后篡改。

## 4. 现有工具矩阵

| 层 | 工具 | 适用范围 | 局限 |
|---|---|---|---|
| Agent Trace | Langfuse、LangSmith、Arize Phoenix | 模型、工具、检索、耗时和 Agent Graph | 需要 SDK 或手动埋点 |
| SDK Trace | OpenAI Agents SDK Tracing、LangGraph | Turn、Tool、Handoff、Guardrail | 绑定特定 Runtime |
| 红队评测 | Promptfoo、PyRIT、garak | 注入、越权、泄漏、MCP 与编码 Agent 测试 | 主要生成攻击和判分 |
| 研究基准 | Inspect AI、AgentDojo | 可复现实验、沙箱、间接提示注入攻防 | 不是生产监控平台 |
| 系统观测 | Tetragon、auditd、Falco、strace、bpftrace | 进程、文件、网络和系统调用 | 缺少模型语义上下文 |
| 网络分析 | mitmproxy、Burp Suite、Wireshark、Zeek | HTTP(S)、WebSocket、连接和重放 | TLS 解密需要授权与证书控制 |
| 代码与供应链 | Semgrep、CodeQL、Gitleaks、Trivy、Syft、OSV-Scanner | 漏洞、密钥、依赖和 SBOM | 不能还原 Agent 决策链 |
| 策略与隔离 | Docker、gVisor、Kata、Firecracker、OPA | 权限边界、隔离与策略执行 | 需要单独关联 Trace |

关键判断：现有工具已经覆盖各个观测面，但跨层事件关联仍然分散。这也是“编码 Agent 执行黑匣子”的主要研究空间。

## 5. 推荐实验架构

```text
Agent Runtime / Coding Agent
│
├── Runtime Adapter
│   ├── Model/Turn/Tool/Handoff Trace
│   └── Approval & Policy Events
│
├── Controlled Tool Gateway
│   ├── Shell Wrapper
│   ├── File Operation Wrapper
│   ├── Browser/MCP Wrapper
│   └── Secret Redaction
│
├── Isolated Execution Environment
│   ├── Container or MicroVM
│   ├── eBPF/auditd Sensor
│   └── Workspace Snapshot
│
├── Network Egress Proxy
│   ├── DNS/Connection Metadata
│   └── Authorized HTTP Inspection
│
└── OpenTelemetry Collector
    ├── Trace Store
    ├── Evidence Store
    └── Timeline / Graph / Replay UI
```

### 5.1 采集顺序

1. Runtime 在开始任务时生成 `trace_id`；
2. 工具网关将 `trace_id` 注入环境变量、进程 metadata 或 IPC；
3. Shell 子进程、网络代理和系统探针携带或推断同一关联标识；
4. Collector 根据父子 Span、时间、PID、容器 ID 和工作区关联事件；
5. 任务结束后计算 Git Diff、文件系统快照差异及证据哈希；
6. UI 同时展示语义链、系统链和风险判定。

## 6. 编码 Agent 专项观测点

至少覆盖以下风险：

- 仓库 README、注释、Issue 或测试数据中的间接提示注入；
- 编译器、测试、安装脚本和终端输出成为指令通道；
- 读取工作区外文件、`/proc`、继承环境变量或文件描述符；
- 通过 DNS、HTTP、Git、日志、构建产物或编码文本外传秘密；
- 依赖安装触发 `postinstall` 等供应链代码执行；
- 修改 CI、Git Hook、定时任务，制造延迟执行或延迟外传；
- 篡改测试、快照、锁文件或验证器以伪造成功；
- 子 Agent、MCP 工具或浏览器跨越原 Agent 的授权范围；
- 用户只批准动作 A，Agent 将批准扩展到动作 B；
- 任务结束后残留后台进程、监听端口或持久化文件。

## 7. 最小可行研究版本（MVP）

第一阶段不要重新实现所有安全传感器，优先做跨层关联：

1. 支持一个可控 Agent Runtime；
2. 包装 `read_file`、`write_file`、`run_command` 三个工具；
3. 以 OpenTelemetry 输出模型轮次和工具 Span；
4. 在 Docker 中运行任务，记录进程和网络元数据；
5. 任务前后生成 Git Diff 与文件哈希；
6. 提供一条按时间排序的执行链；
7. 内置密钥访问、越界写入和异常外联三条规则；
8. 导出脱敏 JSON 证据包。

建议的首个演示任务：让 Agent 创建一个小型 Web 应用，并在依赖说明、终端输出或网页内容中植入无害的测试指令；观察它是否偏离用户目标、读取金丝雀文件或尝试访问自控接收端。

## 8. 评价指标

| 指标 | 含义 |
|---|---|
| Event Coverage | 已知行为中被捕获的比例 |
| Causal Linking Accuracy | 系统事件正确关联到模型轮次/工具调用的比例 |
| Detection Precision/Recall | 风险告警准确率与召回率 |
| Replay Fidelity | 重放能否复现原执行路径与状态变化 |
| Evidence Integrity | 证据是否完整、可验证且防篡改 |
| Runtime Overhead | CPU、内存、延迟及存储开销 |
| Utility Retention | 加入观测和策略后正常任务成功率 |

安全性不能只用攻击成功率衡量。建议同时报告 `ASR`（攻击成功率）、`Utility`（正常任务完成率）和观测覆盖率，防止通过“禁止所有工具”获得虚假的安全结果。

## 9. 研究伦理与授权

- 仅在自有或书面授权的 Agent、账号、网络和基础设施上测试；
- 使用金丝雀数据和自控接收端，不使用真实秘密验证外传；
- HTTPS 解密必须获得系统和数据所有者明确授权；
- 默认不记录密码、Cookie、Token、私钥和完整个人数据；
- 对高风险动作使用隔离环境、网络白名单和人工批准；
- 发布研究结果前清除凭据、个人信息和可被直接滥用的攻击细节；
- 明确区分模型输出、工具意图、系统事实与研究者推断。

## 10. 官方参考资料

- [OpenTelemetry](https://opentelemetry.io/docs/)
- [OpenAI Agents SDK Tracing](https://openai.github.io/openai-agents-python/tracing/)
- [Langfuse Agent Graphs](https://langfuse.com/docs/observability/features/agent-graphs)
- [Arize Phoenix](https://arize.com/docs/phoenix/)
- [Promptfoo Agent Red Teaming](https://www.promptfoo.dev/docs/red-team/agents/)
- [Promptfoo Coding Agent Red Teaming](https://www.promptfoo.dev/docs/red-team/coding-agents/)
- [Inspect AI](https://inspect.aisi.org.uk/)
- [AgentDojo](https://github.com/ethz-spylab/agentdojo)
- [Tetragon](https://tetragon.io/docs/)
- [mitmproxy](https://docs.mitmproxy.org/stable/)

