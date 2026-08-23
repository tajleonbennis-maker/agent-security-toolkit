# 产品化部署指南（长期运行 + 服务器侧视野）

依据 2026-08-23 Kiro 部署监视实战的四条教训改造：

| 实战问题 | v2 方案 | 文件 |
|---|---|---|
| 观察器随会话/进程组被杀，出现监视空窗 | watchdog 守护 + launchd KeepAlive + `--resume` 断链续写 | `kiro/watchdog.sh`、`kiro/install_launchd.sh` |
| Kiro 终端里的 go/git/ssh 是孙进程，网络漏拍 | 全进程树追踪（pid→ppid 可达即目标）+ 网络按当轮实时树归属 | `kiro/observer.py` |
| 告警只能事后 correlator 出，密码已推上 GitHub | 实时规则引擎 + 文件内容密钥嗅探，写入瞬间落盘 | `kiro/observer.py` RealtimeAlerts |
| Kiro SSH 部署到服务器后完全黑箱 | 服务器端采集器（sshd 会话树 + 文件 + 外联）+ 中央汇集 | `server/agent.py`、`server/collect_server.py` |

## 一、本地守护（Mac）

### 快速模式：watchdog

```bash
cd beats-agent-tracker
bash kiro/monitor_kiro.sh /path/to/workspace   # 内部 exec watchdog.sh
```

- 观察器异常退出（含 kill -9）→ 1 秒内拉起，`--resume` 续写同一 trace_id，哈希链无缝
- 优雅停止：`touch events/STOP`（观察器收尾出报告后退出，watchdog 退出）
- 退出码约定：42 = 优雅停止；其他 = 崩溃（重启）

### 产品模式：launchd（系统级守护）

```bash
bash kiro/install_launchd.sh /path/to/workspace      # 安装并启动
bash kiro/install_launchd.sh --uninstall             # 卸载
```

- KeepAlive：哪怕整个进程组被 SIGKILL，launchd 立即重新拉起
- 日志：`~/Library/Logs/agent-monitor/observer.log`

### 观察器 v2 关键参数

```bash
python3 kiro/observer.py --workspace WS [选项]
  --seed-pid PID         监视任意 Agent（不限于 Kiro）：给它的主进程 pid
  --seed-pattern PREFIX  种子进程 argv 前缀（默认 /Applications/Kiro.app）
  --resume TRACE_ID      断点续写（watchdog 自动使用）
  --poll-proc 0.5        进程轮询秒（默认 0.5，短命孙进程不漏）
  --poll-net  0.3        网络轮询秒（默认 0.3）
```

实时告警：观察器运行期间命中规则立即打印 `🚨 [R1/R2/R3]` 并写入
`events/<trace_id>_alerts.ndjson`——进程被杀，告警仍在磁盘上。

内容嗅探模式（R1 增强）：新写 ≤256KB 的文本文件命中以下模式即报——
私钥头、AWS AccessKey、GitHub token、sshpass 明文密码、
`password/secret/token = ...` 赋值。**只记录模式名和行号，不落密文本身。**

## 二、服务器侧采集（被部署主机）

部署（在被监视的 Mac 上执行，需要 SSH 凭据）：

```bash
bash server/install.sh root@102.134.48.49 [ssh端口]
```

在服务器上做的事：`agent.py` → `/opt/agent-monitor/`，systemd 单元
`agent-monitor.service`（root、Restart=always、开机自启）。

采集范围：

- **SSH 会话**：`sshd: user@pts/N` 会话进程的完整进程树——远端 Agent 在
  SSH 里跑的每条命令（git/systemctl/curl/scp…）都是子孙，逐个 process.spawn
- **网络**：`/proc/net/tcp(+6)` ESTABLISHED + `/proc/*/fd` socket inode 映射，
  会话树内进程的外联（数据外传可见）
- **文件**：`--watch /opt,/srv,/root,/var/www,/home` walk-diff
- **内容嗅探**：同本地（remote-deploy.sh 带密码落盘的瞬间报警）

服务器侧操作：

```bash
journalctl -u agent-monitor -f              # 实时日志
cat /var/lib/agent-monitor/events/srv_*.ndjson   # 事件流（哈希链防篡改）
touch /var/lib/agent-monitor/STOP           # 优雅停止
```

## 三、中央汇集（可选，事件回传监视机）

```bash
python3 server/collect_server.py --port 8787        # Mac 上跑
# 服务器端配置上报（改 systemd 单元 ExecStart 追加）：
#   agent.py --report-url http://<Mac的IP>:8787/ingest
```

- 每批上报做哈希链连续性校验（防传输篡改/乱序），断裂即告警
- `GET /status` 查看各源状态

## 四、多源合并报告（本地 + 服务器联合时间轴）

```bash
python3 correlator/correlate.py \
  --input events/kiro_xxx.ndjson,events/srv_yyy.ndjson \
  --out output/report
```

- 双链各自校验完整性，报告标注全部监视主机
- 实时告警文件（`*_alerts.ndjson`）自动合并进 alerts.json

## 五、已知边界

- 被动模式仍看不到 LLM 语义（prompt/响应），需 MITM 升级
- macOS 文件读取（open）监控需 fs_usage + sudo，当前只覆盖增删改
- 服务器端 /proc 轮询间隔 0.5s，亚秒级短命命令仍可能漏拍（可用 auditd/eBPF 升级）
- lsof 轮询同理；追求零漏拍需 EndpointSecurity Framework（需签名授权）
