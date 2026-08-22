# Agent Security Toolkit（智能体安全研究与评估工具包）

中文智能体（AI Agent）安全研究资料合集，共四份配套文档，从攻防全景到落地评估手册形成完整链路。

> ⚠️ 本仓库内容仅用于**授权安全评估**与防御研究。所有攻击手法描述均为防御目的的测试模式，使用前必须获得目标系统所有者的书面授权。

## 文档目录

| 文档 | 内容 |
|------|------|
| [01. OWASP 智能体十大安全风险与真实事件详解](./01-OWASP-Agentic-Top10-Incidents.md) | OWASP Top 10 for Agentic Applications 2026（ASI01–ASI10）逐项解析，覆盖 13 个真实攻击事件（EchoLeak、LiteLLM 供应链投毒、Replit 删库、Arup 深度伪造等）的完整攻击链与时间线 |
| [02. 国内 Agent 安全研究全景](./02-China-Agent-Security-Landscape.md) | 国内学术界五大方向（IPI 攻防、轨迹级评测、全栈防护、AI 攻防评测、前沿失控风险）、产业界三条路线（蚂蚁/斗象/深信服）、标准治理布局（信通院/TC260/WDTA），及与 OWASP ASI 的映射表 |
| [03. 国内主流 Agent 产品盘点](./03-China-Agent-Products-Survey.md) | 七大类别 40+ 产品：通用自主智能体（OpenClaw/Manus/Kimi）、编程智能体、Coding Plan 价格战、手机端侧智能体、企业级平台、开源自托管，及趋势观察与选型速查表 |
| [04. Agent 安全评估实战指南](./04-Agent-Security-Assessment-Guide.md) | 基于 OWASP ASI 2026 的完整评估方法论：法务授权前提、六阶段流程、四层攻击模型、ASI01–10 逐项测试用例库（含 Pass/Fail 信号）、工具箱、ASR×Utility 指标体系、报告模板 |

## 推荐阅读顺序

```
01 十大风险（是什么威胁）
   → 02 国内研究全景（谁在研究）
   → 03 产品盘点（评估对象是谁）
   → 04 评估指南（怎么测）
```

## 参考框架

- [OWASP GenAI Security Project](https://genai.owasp.org) — Top 10 for Agentic Applications 2026
- [MITRE ATLAS](https://atlas.mitre.org)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- 信通院《可信AI云 智能体质效与安全能力要求》系列标准

## License

MIT
