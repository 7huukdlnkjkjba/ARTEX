# Metasploit 全自动闭环（msf）

本页说明 ARTEX 如何把 **mcp-pymetasploit3**（Metasploit RPC 的 MCP 封装）接入 Worker，
并用一个**确定性决策层**把「漏洞 → 模块 → 参数 → 执行 → 会话」串成可复现的闭环。

```
┌──────────── ARTEX Worker ────────────┐
│ 1. msf_plan    （纯决策，无网络）      │  漏洞类别/目标 → 候选模块 + 参数 + 前置条件 + 失败分支
│ 2. msf_execute （自动执行候选链）      │  连 MCP → use_module → set_option → execute → list_sessions
│ 3. 写回 fact / 登记 ARTEX 会话        │  session id、主机、权限、可达网段
└───────────────┬──────────────────────┘
                │ stdio MCP (JSON-RPC)
        ┌───────▼────────┐      msfrpc       ┌──────────────┐
        │ mcp-pymetasploit3 │ ───────────────▶ │ msfrpcd (55553) │
        └────────────────┘                  └──────┬───────┘
                                                   │
                                            Metasploit Framework
```

## 1. 安装与接入（零人工，默认全自动）

### 1.1 Metasploit RPC：ARTEX 自己拉起

**不需要手工执行 `msfrpcd`**。ARTEX 启动时会：

1. 探测 `127.0.0.1:55553`；已有外部 msfrpcd 就直接复用（`managed=false`）。
2. 没有则定位 `msfrpcd`（PATH / `METASPLOIT_ROOT` / `C:\metasploit-framework\bin`），
   生成 32 位随机密码并写入 `settings.msf_rpc_password`，以
   `msfrpcd -P <pw> -p 55553 -S -n -a 127.0.0.1` 启动（仅 loopback、明文）。
3. 最多等 90s 等 RPC 就绪；失败只记日志，不阻塞 ARTEX 启动。
4. ARTEX 退出时回收自己启动的进程（外部复用不动）。

可用环境变量微调：`ARTEX_MSF_AUTOSTART=0` 关闭自动启动、`ARTEX_MSF_RPC_PORT` 改端口、
`ARTEX_MSF_RPC_ADDR` 改地址、`ARTEX_MSF_RPC_PASSWORD` 指定密码。

### 1.2 MCP 服务：不需要在 UI 里配置，也不需要手工装包

首次启动时如果检测不到 `mcp-pymetasploit3`，ARTEX 会在后台自动执行：

```bash
pip install "mcp-pymetasploit3[mcp]"
```

- 最长 5 分钟，失败只记日志，不影响 ARTEX 启动；
- `ARTEX_MSF_AUTO_INSTALL=0` 关闭自动安装；
- `ARTEX_MSF_PYTHON=/path/to/python` 指定解释器或 venv（指定后只认该解释器，忽略 PATH 上的 console 脚本）。

> 手动安装等价于 `pip install "mcp-pymetasploit3[mcp]"`；`[mcp]` extra 会带上 `fastmcp`，
> 缺它时 `import mcp_pymetasploit3` 会失败。

ARTEX 启动时会种入一条 disabled 的 `metasploit` MCP 配置；但 `msf_execute` **不依赖它**：
找不到启用的 MCP 行时，会直接用内置启动器拉起 `mcp-pymetasploit3`（console 脚本优先，
否则 `python -m mcp_pymetasploit3`）。所以无需「系统 → MCP」启用、也无需给 worker
授权 MCP 工具可见性——闭环工具是 ARTEX 的 host 工具（`msf_plan`/`msf_next`/`msf_execute`），
内部直接调用 MCP。

> 如果确实想用「系统 → MCP」统一管理/看工具，也可以在那里启用内置 `metasploit`；
> 两种方式等价，内置启动器只是兜底。

### 1.3 RPC 密码

`msf_execute` 按以下顺序取密码：

1. 入参 `rpc_password`
2. 环境变量 `ARTEX_MSF_RPC_PASSWORD`
3. 设置项 `msf_rpc_password`（自动启动时生成并写入）
4. 受管进程内存中的密码

密码不会写进日志；MCP 的 `connect` 调用只在首次连接时发生。

### 1.4 全自动触发（AI 自己开始）

不需要人去点「确认漏洞」再手动派单：

- 验证器（`record_finding_check_result` → `verified`）把漏洞置为 confirmed 时，
  服务端回调 `OnFindingConfirmed` → `msfAutoKick`。
- 人工在 UI 把漏洞状态改为 confirmed 也会触发同一逻辑。
- `msfAutoKick` 直接向 frontier 下发一条高优先级意图（origin=`msf`，锚定漏洞节点与资产，
  summary 自带类别、目标与执行纪律），worker 池会直接领取，不再依赖下一轮 planner 派单；
  同时写一条 hint 告知 planner「已派发、勿重复」。同一漏洞已有 open/running 的利用意图
  时跳过；写意图失败则退回 hint 路径，不会静默丢掉闭环。
- worker 调 `msf_plan` → `msf_execute`；`msf_execute` 拿到 session 后自动采集证据并写回 fact。

也就是说：**人只需要给目标与授权范围，剩下由 planner/worker 的 AI 闭环完成**。
`msf_execute` 仍是 host 工具（不是 MCP 工具透传），所有结果都进 transcript/fact，可审计。

## 2. 决策层（`msf/`）

决策是**纯函数**：同一输入永远得到同一 `plan_id`、同一候选顺序、同一分支，不依赖模型采样，
因此 planner/worker 重启后可以重算同一计划。

### 2.1 输入

`vuln_class`（类别/产品/CVE 自由文本，内部归一化）、`host`、`port`、`service`、`url`、
`lhost`/`lport`。类别归一化覆盖：struts2、log4j、weblogic、tomcat、spring、jenkins、shiro、
activemq、solr、confluence、eternalblue(MS17-010)、bluekeep(CVE-2019-0708)、vsftpd、redis、
ssh/mysql/mssql/smb 口令类。

未命中内置类目时返回 `kind=search` + `suggested_search`，要求先用 `search_modules` 检索，
**不猜模块名**。

### 2.2 输出（节选）

```json
{
  "plan_id": "msf-1a2b3c4d5e6f",
  "kind": "exploit",
  "class": "struts2",
  "candidates": [
    {"order":1,"module_type":"exploit","module":"exploit/multi/http/struts2_content_type_ognl",
     "payload":"linux/x64/meterpreter/reverse_tcp",
     "options":{"RHOSTS":"10.0.0.5","RPORT":"8080","TARGETURI":"/app/login.action","LHOST":"10.0.0.1","PAYLOAD":"..."},
     "confidence":80,"rationale":"Content-Type OGNL 注入，覆盖 S2-045/S2-046 系"}
  ],
  "preconditions":["port_open:10.0.0.5:8080","module_exists: ...","callback_reachable:10.0.0.1:4444"],
  "branches":[
    {"on":"module_missing","do":"retry_next"},
    {"on":"precheck_failed","do":"degrade"},
    {"on":"no_session","do":"retry_next"},
    {"on":"session","do":"post_session"},
    {"on":"exhausted","do":"stop"}
  ],
  "session_post":["sysinfo / whoami","getuid","ipconfig / ifconfig","写回 fact"]
}
```

### 2.3 失败分支（`msf_next`，确定性）

| 观察结果 | 动作 | 语义 |
|---|---|---|
| `session` | `session` | 拿到会话 → `msf_execute` 已自动取证并写回 fact |
| `module_missing` | `retry` | 当前 MSF 没有该模块 → 下一候选 |
| `precheck_failed` | `degrade` | 前置条件不满足 → 转 check/辅助验证，写否定 fact |
| `no_session` | `retry` | 模块跑完无会话 → 下一候选（换利用面/payload） |
| `error` | `retry` | RPC/模块报错 → 下一候选 |
| 候选耗尽 | `stop` | 写否定 fact（模块+参数+原因），禁止重复同一路径 |

## 3. 工具契约

| 工具 | 读 | 作用 |
|---|---|---|
| `msf_plan` | ✅ | 只读决策：候选模块、参数、前置条件、分支、取证步骤 |
| `msf_next` | ✅ | 无状态分支选择：传同一目标 + `attempt` + `outcome`，返回下一步动作 |
| `msf_execute` | ❌ | 全自动执行候选链：连 MCP → use_module → 设参 → execute → 轮询会话；返回 transcript 与 session id |

`msf_execute` 的硬边界：

- **scope 门**：目标必须落在任务已登记的 `task_scope` 内；任务没有任何 scope 时放行并记审计
  （bootstrap 阶段），越界直接拒绝。
- 只应在**漏洞已确认**之后调用；它不负责发现漏洞。
- 每轮默认最多试 3 个候选（上限 8），等待会话默认 25s（上限 120s）。
- 执行结果（含失败）应写回 fact，形成「尝试过什么」的可审计链路，避免 planner 重复派单。

## 4. Worker 闭环用法（AI 自动执行，无人工步骤）

触发由系统完成（验证器/UI 确认漏洞 → `msfAutoKick` → 直接下发 worker 意图，详见 §1.4）。
Worker 拿到意图后：

1. `msf_plan` 拿计划（或 planner 已给出 `vuln_class`）。
2. `msf_execute` 自动跑；返回 `sessions` 非空即成功。
3. **拿到会话时 `msf_execute` 已自动取证**：对每个新会话执行
   `id/whoami/hostname/uname/ip` 只读命令，并把输出随结果的 `transcript[].evidence` 返回。
4. **自动写回 fact**：会话 id、类别、目标、取证输出写入探索图
   （`confidence=confirmed`，带 `msf_session_id`/`msf_plan_id`），并唤醒 planner，
   即使模型没有补发一轮也不会丢证据。
5. 若拿到的是可交互 shell，登记 ARTEX 会话（`register_session`）或按 MSF 会话继续操作。
6. 失败则按 `action.kind`（retry/degrade/stop）处理，**不要**原样重试同一候选。

## 5. 限制与注意事项

- **MCP 的模块工具是无状态的**：`set_module_option` 每次都会重新 `modules.use(...)`，跨调用设置的
  `TARGETURI`/`SSL` 等不会保留。因此 `msf_execute` 走 **console 路径**（同一 console 内
  `use` → `set ...` → `run -j`），只有 console 不可用时才退回 `execute_module`（只支持
  rhosts/rport/lhost/lport/payload，其余参数会丢失）。
- **RPC SSL**：默认 `msfrpcd` 开 TLS，`msfrpcd -S` 是明文。`msf_execute` 默认 `rpc_ssl=auto`
  （先 TLS 再明文），也可用 `rpc_ssl` 入参或 `ARTEX_MSF_RPC_SSL=true|false` 固定。
- 模块路径随 MSF 版本变动；执行前会 `get_module_info` 校验，缺失自动走 `module_missing`。
- 反弹 payload 需要目标能回连 `LHOST`；内网场景先建隧道再给 `LHOST` 为平台可达地址。
- 高交互/加固目标可能「check 通但拿不到会话」，此时按 `degrade` 写否定结论，不无限重试。
- 该闭环默认不走 ARTEX 的 `reverse_listen`/penelope；MSF 会话由 Metasploit 托管，
  需要转入内网作业时用 `session_run_command` 或把凭据/拓扑写回资产图。
- 合规：仅对授权目标使用；`msf_execute` 受任务 scope 硬校验，但使用者仍需自行确认授权。
