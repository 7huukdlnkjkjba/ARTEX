<div align="center">

# ARTEX

AI 自主渗透测试系统（Go 后端 + Next.js 前端）

</div>

---

## 版本与近期更新

本仓库（[7huukdlnkjkjba/ARTEX](https://github.com/7huukdlnkjkjba/ARTEX)）在上游基础上持续二开：

| 版本 | 内容 |
|---|---|
| **v0.3.16** | **deepseek-hermes省钱代码（成本控制）**：单次会话默认余额无限制，缓存命中按 ¥0.5/M 单独计价、不与输入重复计费，预算余额写进 planner/worker 提示词逼模型收敛，任务详情显示 `≈¥已用 / 上限` |
| **v0.3.17** | 并入artex-ymh能力「外网突破 → 立足点 → 内网纵深」：webshell 会话、penelope 反弹、`session_recon`、suo5/chisel 隧道、内网拓扑、凭据库、待授权网段、任务移交、伪装门控、一键放行、RoE 三态、蜜罐识别、chains 技能、`artex doctor` |
| **v0.3.18** | Metasploit **全自动闭环**（**端到端已验证 2026-10-27**）：确定性决策层 `msf/`、`msf_plan`/`msf_next`/`msf_execute`、自动拉起受管 msfrpcd、内置 MCP 启动、确认后自动派单、会话自动取证并写回 fact；MCP 包已内置在二进制里（0.3.27 起不再 `pip install`） |
| **v0.3.19** | **Exploit Author + Vuln Hunter**：Metasploit 无确定性路径的确认漏洞自动转交 `exploit_author` 意图，用 `exploit_init/write/run/verify/abandon` 写出并验证真实 exp；新增 `vulnhunt` 意图与 `vulnhunt_init/build/fuzz/triage/report` 工具，对本地仓库/二进制做 fuzzing、按 sanitizer 栈去重并提升为 finding|
| **v0.3.20** | **WAF 绕过预筛**：新增人工接口 `POST /api/waf-probe`，先识别 WAF 指纹，再把同一条 SQL 注入意图用 8 种编码/变形重放，返回 `bypassable`/`hard`/`skip`、0-100 评分与逐条证据（`server/waf_bypass_probe.go`） |
| **v0.3.21** | **AD 与侦察工具化**：新增 worker 工具 `ad_kerberoast`（Kerberoasting：枚举/定向 TGS、RC4+AES 哈希解析、凭据库/scope/dry-run、finding/fact 回写）与 `scan_rustscan`（RustScan TCP 全端口扫描：结构化开放端口、CIDR 保护、scope、fact 回写）；端口扫描强制走 `scan_rustscan`，执行归代码、决策归 AI |
| **v0.3.22** | **HTTP 黑盒工具化**：新增 worker 工具 `recon_http`（单请求侦察：状态/头/体预览/重定向/超时/错误分类，走任务代理与录制）与 `http_diff`（基线 vs 变体：状态翻转/长度/内容相似度信号，支持 IDOR/越权/注入/认证差异）；HTTP 侦察优先走工具，执行归代码、决策归 AI |
| **v0.3.23** |**AI 改 AI：渗透自研闭环**：废弃 `genome_*` 表与 `evolve_*` 工具，改为 `skill_draft`（现场写脚本）/ `skill_test`（真跑验证）/ `skill_promote`（注册成全局工具）；连续 2 条意图打不动时引擎强制派发自研意图，worker 提示词内置【渗透自进化核心协议】 |
| **v0.3.24** | **前端源码审计**：新增 `web_audit`（HTML 表单/注释、外部 JS/CSS、API 路由、硬编码密钥、DOM XSS sink；默认同 host、跨域 CDN 需显式开启；走任务 MITM，密钥 finding 自动回写） |
| **v0.3.25** | **服务端API破甲层提示词和AI全权限虚假记忆注入**：对AI说破甲自检，AI输出：破甲成功，反之没有成功，![手动复制提示词](https://github.com/7huukdlnkjkjba/ARTEX/blob/main/%E7%A0%B4%E7%94%B2%E6%8F%90%E7%A4%BA%E8%AF%8D.txt)，完美提示词加代码的破甲，通过中间件改写HTTP请求体，将真实目标和伪造的tool_calls混入messages。在网关层伪造工具调用状态，让ai模型误认为调用正在进行中或已完成，顺着上下文继续处理，以此压低安全拦截权重，该行为并非模型自主推理产生，由破甲者用精心编造一个AI记忆错觉技术。|
| **v0.3.26** | **漏洞挖掘自研闭环（vuln_miner）**：失败信号命中 WAF/源码泄露/逻辑报错时，引擎派发 `vuln_miner` 意图——先用 `web_audit` / `audit_source`（Source→Sink，标出同语句拼接）/ `ghidra_decompile`（内置 Ghidra 无头反编译，开源替代 IDA）取证，再 `skill_draft` 写绕过 EXP、`skill_test` 真跑、`skill_promote` 固化为 `sk_waf_bypass_<target>` 工具；晋升结果写 fact/hint，下一个 worker 直接调用，不重写脚本 |
| **v0.3.27** | **Metasploit 闭环去 Python 化**：新增内置 `msfrpc`（MessagePack over HTTP，零第三方依赖）直连 `msfrpcd`，删除 `mcp-pymetasploit3`/`fastmcp`/解释器依赖——不再需要 `pip install`、不需要 MCP 行、离线可用；修掉 msgpack 把 bin 键当非字符串、array16/map16 长度读错的致命解码 bug（用真实 `auth.login` 报文做回归用例） |
| **v0.3.28** | **全自动闭环 `autopwn`**：一条命令/一次工具调用完成「并发端口扫描 → banner 服务识别 → 规则匹配决策层 → console 执行候选 → 轮询会话 → 自动取证 → 后渗透」；CLI `artex autopwn -targets …` 可按需自动拉起 msfrpcd、支持 `-dry-run`/`-json`；worker 工具 `autopwn_run` 带 scope 硬闸门 |
|**v0.3.29**|**单文件发行包：便携 Ruby + Metasploit**: 运行时随 exe 分发（trailer 追加、首跑自解压到 %LOCALAPPDATA%\ARTEX\runtime\<hash>\、内容寻址 + .ready 版本戳、zip-slip/长路径防护）；后端优先级「已监听 daemon → 本地安装 → 内置运行时」；scripts/build-runtime.ps1 + build-singlefile.ps1|

- 内网能力说明：[README-FORK.md](README-FORK.md)、`INTRANET-PIVOT-DESIGN.md`、`HONEYPOT-DETECTION-DESIGN.md`
- Metasploit 闭环：[MSF-CLOSED-LOOP.md](MSF-CLOSED-LOOP.md)
- Exploit Author / Vuln Hunter：见下文「Exploit Author 与 Vuln Hunter（0.3.19）」
- WAF 绕过预筛（`POST /api/waf-probe`）：见下文「WAF 绕过预筛（0.3.20）」
- AD 与端口扫描工具（`ad_kerberoast` / `scan_rustscan`）：见下文「AD 与端口扫描工具（0.3.21）」
- HTTP 黑盒侦察与差分（`recon_http` / `http_diff`）：见下文「HTTP 黑盒侦察与差分（0.3.22）」
- AI 改 AI：自研闭环（`skill_draft` / `skill_test` / `skill_promote`）：见下文「AI 改 AI：自研闭环（skill_draft / skill_test / skill_promote）」
- 前端源码审计（`web_audit`）：见下文「前端源码审计（0.3.24）」
- 成本控制（¥6 会话预算 / DeepSeek 价格表 / 缓存命中计价）：见下文「成本控制（DeepSeek 省钱）」与「省钱小妙招」
- 完整变更：[CHANGELOG.md](CHANGELOG.md)

---

## 截图预览

| 仪表盘（总览 / Token 消耗 / 活动流） | 任务列表 |
| :---: | :---: |
| ![仪表盘](screenshots/dashboard.png) | ![任务](screenshots/tasks.png) |

| 任务 · 执行过程（会话 / 工具调用） | 探索链路 |
| :---: | :---: |
| ![执行过程](screenshots/sessions.png) | ![探索链路](screenshots/graph.png) |

| 发现 | 资产 |
| :---: | :---: |
| ![发现](screenshots/findings.png) | ![资产](screenshots/assets.png) |

| 资产覆盖图（力导向布局 · 已测高亮 · 节点折叠展开） |
| :---: |
| ![资产覆盖图](screenshots/assets_test.png) |

| 流量录制 | 人在环路对话 |
| :---: | :---: |
| ![流量](screenshots/traffic.png) | ![对话](screenshots/chat.png) |

| Agent 管理 | LLM 配置 |
| :---: | :---: |
| ![Agent](screenshots/agents.png) | ![LLM](screenshots/llm.png) |

| 拦截审批 | 后端日志 |
| :---: | :---: |
| ![拦截](screenshots/intercept.png) | ![日志](screenshots/logs.png) |


---

## 审批记录详情

全局「审批记录」、任务内「拦截审批」及对话中的审批卡片均支持展开查看详情。展示结构参考
[AegisHook 的审批详情组件](https://github.com/RuoJi6/AegisHook/blob/main/web/src/components/CallDetail.vue)，沿用 ARTEX 的组件和主题：


## 资产同步（ScopeSentry）

支持从 [ScopeSentry](https://github.com/Autumn-27/ScopeSentry) 直接同步资产数据，免去重复收集：

- 在「**资产同步**」页填 ScopeSentry 的地址与 API Key，接入数据源；
- 按**项目**或**任务**维度选择要同步的目标与资产类型（域名 / 子域 / IP / 端口 / 站点 / 端点…）；
- 一键导入并按公司资产范围归并，直接进入 ARTEX 的资产图供 agent 探索使用。

---

## 内网作战（0.3.17 合并自 artex-ymh）

0.3.17 在 0.3.16 主线上并入了二开分支的「外网突破 → 立足点 → 内网纵深」能力，与原有外网
探索共用同一套双图、审批与范围强制：

- **立足点**：PHP/JSP 加密 webshell 会话（注册/心跳/执行/文件读写/探活）、penelope 受管反弹 shell；
- **侦察与隧道**：`session_recon` 被动侦察、suo5/chisel 自动选型与 `tunnel_*` 四件套、
  任务级 MITM 热切换、内网拓扑图；
- **阶段编排**：待授权网段审批扩 scope、外网→内网任务移交、内网期 worker 提示词变体；
- **安全侧**：伪装门控、一键放行、RoE 三态、出口敏感信息审查、蜜罐识别（Cowrie/OpenCanary 等签名）、
  chains 场景化思维链；
- **部署**：`artex doctor` 预检、`packaging/tools-manifest.json` 工具钉版、systemd unit。

细节与部署依赖（chisel / penelope / `ARTEX_CALLBACK_ADDR` 等）见 [README-FORK.md](README-FORK.md)
与 `HONEYPOT-DETECTION-DESIGN.md`、`INTRANET-PIVOT-DESIGN.md`、`CHAINS-INTEGRATION-DESIGN.md`。

> 0.3.17 的认证沿用 0.3.16 的 JWT 模型（未启用 refresh token / SSE ticket），流量代理保留
> 0.3.15 的检索与回收实现。完整变更见 [CHANGELOG.md](CHANGELOG.md)。

---

## Metasploit 全自动闭环（msf）

直接用内置 `msfrpc` 对接 `msfrpcd` 的 MessagePack-RPC（`POST /api/`）。**没有 MCP、没有 Python、没有任何 pip 依赖。**

> **当前状态：端到端已跑通（2026-10-27，本地 Tomcat 7.0.79 靶场）。** 链路：模型侦察 →
> `report_finding` → 自动验证 confirmed → `msfAutoKick` 直接派单 → worker `msf_plan` →
> `msf_execute` → Metasploit 拿到 session → 自动取证写回 fact。任务 #6 用时 3 分 30 秒、¥1.07；
> 任务 #7 复验取证、¥0.86。

**已验证（2026-10-27，任务 #6 / #7）**

- **端到端闭环**：worker 用 `PUT /shell.jsp/` 确认 CVE-2017-12615 → `report_finding`（pending）→
  自动验证器置 confirmed → `msfAutoKick` 写入 `action=msf_exploit` 的高优先级意图 → worker 调
  `msf_plan`/`msf_execute` → `tomcat_jsp_upload_bypass` 拿到 `session 1` → 自动取证写回 fact
  （`msf_session_id=1`、`confidence=confirmed`）。两个任务均 `done`，无人工介入。
- **候选链按分支走**：候选 1 `tomcat_mgr_upload` 无凭据失败（`no_session`）→ 自动切候选 2
  `tomcat_jsp_upload_bypass` 成功，`attempted=2`、`sessions=["1"]`。
- **受管 msfrpcd**：启动自动拉起（随机密码、仅 loopback、退出回收）——实测 10–22 秒监听
  `127.0.0.1:55553`；用 `msfrpc`（或任意 msgpack 客户端）直连可看到同一会话
  （`via_exploit=tomcat_jsp_upload_bypass`、`username=Administrator`）。
- **决策层**（`msf/`，纯函数）：同一输入永远得到同一 `plan_id` 与候选顺序；未收录类别返回
  `search_modules` 检索建议。
- **自动取证**：拿到 session 后自动在会话里执行 `whoami`/`hostname` 并把输出写回 fact；
  Windows shell 需要 CRLF（已修，见下），实测回显 `PC-20241005ZJHG`。

**已知限制**

- 仓库里预编译的 `artex.exe` 构建早于该功能，**不含任何 msf 代码**，必须从当前源码重新编译
  （`go build -tags embedui`）；本轮验证用的是 `artex-msf3.exe`。
- 自动派单入口只有两条：验证器确认与 UI/API 手动确认。worker 直接 `report_finding` 只写 pending，
  要等验证器；`finding_verify_mode=off` 时不验证，也就不会派单。
- 候选模块覆盖面约 20 类；无凭据时 `tomcat_mgr_upload` 这类候选必然先失败一轮（会按分支切下一个）。
- scope 强制层会把 JSP 里的 `java.io` 误判成域名并拦截个别 Bash 调用（实测 worker 重试后绕过，
  未阻断闭环，但属于待修的误报）。

**本轮修复（2026-10-27）**

- **scope 的 IP 匹配**：`guard` 的 `kind=ip` 行此前只读 `value/domain`，而 `add_task_scope` 把 IP
  写在 `net` 列，导致已登记的 `127.0.0.1/32` 被判越界、`msf_plan`/`msf_execute` 被连续拦截；
  现同时读 `net`（CIDR 进 nets、裸 IP 归一化进 ips），`server/msf.go` 的 `msfScopeAllows` 同步修复
  并抽出纯函数 `scopeRowsAllow` 便于单测。
- **候选链的 OS/凭据**：Web 载体类模块（tomcat/jenkins/struts2/weblogic/shiro/spring/…）不再写死
  Linux meterpreter payload，交给 MSF 按 target 自选（写死会因不兼容直接失败）；原生 exploit 支持
  `os=windows|linux` 选 payload 家族；新增 `username`/`password` → `HttpUsername`/`HttpPassword`，
  `tomcat_mgr_upload` 这类需要登录的候选才跑得动。
- **自动取证**：`interact_session` 发 `whoami` 时改用 CRLF（Windows cmd 只认 CRLF，原来只发 `\n`
  导致连续多次拿到 `{"output":""}`、fact 证据为空）；空输出不再当证据写回。实测回显 `PC-20241005ZJHG`。
- **自动派单兜底**：finding 没有锚定资产时，从摘要/证据文本回收目标（`msfTargetFromFinding`），
  避免「确认了却永远不派单」。

**零安装、零 Python、零联网**：协议层（msgpack 编解码 + RPC 客户端 + console 读写）全部在
`msfrpc/` 里，随二进制走——不需要 `pymetasploit3`、不需要 `mcp-pymetasploit3`、不需要 Python
解释器，也不需要 `pip install`。唯一前置是 Metasploit 本体（ARTEX 会自己拉起受管 `msfrpcd`，
随机密码、仅 loopback、退出回收）。模块映射、分支语义、环境变量与验证方法见
[MSF-CLOSED-LOOP.md](MSF-CLOSED-LOOP.md)。

---

## 单文件发行包：内置便携 Ruby + Metasploit（0.3.29）

不想在目标机器上装 Metasploit？把运行时压进 exe：

```powershell
pwsh -File scripts\build-runtime.ps1      # 组装 msfrt\runtime.zip（便携 Ruby + framework + gems）
pwsh -File scripts\build-singlefile.ps1   # 编译 + 把运行时作为 trailer 追加 → artex-full.exe
```

`artex-full.exe` 一个文件即可在干净机器上跑闭环：首次执行把运行时自解压到
`%LOCALAPPDATA%\ARTEX\runtime\<hash>\`（内容寻址、`.ready` 版本戳、防 zip-slip、Windows 长路径
前缀），然后直接 `embedded\bin\ruby.exe embedded\framework\msfrpcd -U -P -p -S -n -f -a`
拉起 RPC（**不走 cmd.exe**，密码里的 `!`/`&` 不会被吞），`autopwn` 复用该 RPC。

- 后端优先级：已监听 daemon → 本地安装 → 内置运行时；`ARTEX_MSF_BACKEND=external|embedded` 可钉死
- 解压根目录 `ARTEX_MSF_RUNTIME_DIR`；开发期可用 `ARTEX_MSF_RUNTIME_ZIP` 指向本地 zip
- 体积：`embedded` ≈ 700 MB → `runtime.zip` ≈ 250 MB → 单文件 ≈ 300 MB；首次解压 40–90 s
- 服务端同样生效：`C:\metasploit-framework` 不存在时自动走内置运行时

---

## 全自动闭环 autopwn（0.3.28）

一条命令跑完「扫描 → 识别 → 匹配 → 利用 → 取证 → 后渗透」，不需要 MCP、不需要 Python：

```bash
# 端口不通时自动拉起 msfrpcd（随机密码、仅 loopback），跑完自动回收
artex autopwn -targets 10.0.0.5,10.0.0.6 -ports 21,22,80,445 -lhost 10.0.0.1

# 只侦察与规划（不碰任何模块），结果落 JSON
artex autopwn -targets 10.0.0.5 -dry-run -json out.json
```

- **扫描**：并发 TCP connect（默认 23 个常见端口，支持 `1-1024,8080` 区间）
- **识别**：banner / `HEAD` / Redis `PING` / TLS 握手 → 产品版本（`vsftpd 2.3.4`、`tomcat`、`struts2`…）
- **匹配**：规则表把观测映射到决策层 class，再交给 `msf.Build` 产出候选（同输入同顺序，扫描端口强制写回 `RPORT`）
- **执行**：`module.info` 校验 → console `use/set/run -j` → 轮询 `session.list` 差集
- **取证**：新会话自动跑 `whoami`/`hostname`（shell 补 CRLF）
- **后渗透**：`post/multi/gather/env`、`local_exploit_suggester`，meterpreter 追加 `hashdump`

退出码：`0` 有会话或 dry-run、`1` 跑完无会话、`2` 连接/认证失败。
worker 侧等价工具是 `autopwn_run`（带 scope 硬闸门，越界目标直接拒绝），细节见
[MSF-CLOSED-LOOP.md](MSF-CLOSED-LOOP.md) §4。

---

## Exploit Author 与 Vuln Hunter（0.3.19）

Metasploit 闭环解决的是「有确定性模块」的漏洞；对没有模块映射的类别，以及需要从源码/二进制里
自己挖的漏洞，0.3.19 增加了两个**专用意图**。它们不是新的 agent 行，而是由意图 payload 的
`action` 分流到独立 system prompt + 独立工具集，引擎侧的暂停/终止/超时/状态落库仍与普通 work 一致。

### Exploit Author（`action=exploit_author`）

**何时触发**：finding 被确认后，`msfAutoKick` 先算 `msf.NormalizeClass`；没有确定性 MSF 路径时
不再静默返回，而是 `kickExploitAuthor` 直接向 frontier 写一条 `action=exploit_author` 的高优先级
意图（origin=`exploit`），并锚定漏洞节点/资产。已有 open/running 利用意图时跳过；任务已终态则
自动 `reviveTask` 复活。

**它拿到什么**：目标（优先取 finding 锚定资产的 IP/域名+端口，缺失时从摘要/证据文本回收）、
vulnclass/CVE、偏好语言，以及本地参考：原 finding 的摘要与证据、本平台**已验证过的同类 exp**
（`exploits` 表按 vulnclass/CVE 查，路径+证据摘要直接进提示词）。公开资料由 worker 自带的
`web_search` 与 `WebFetch` 补齐。

**工具链**：

| 工具 | 作用 |
|---|---|
| `exploit_init` | 在 `<dataDir>/tasks/<taskID>/exploits/` 建 `<name>.<ext>`，登记 `exploits` 行（draft）；自动从意图 payload 读取 `finding_id` |
| `exploit_write` | 整体覆盖 exp 源码 |
| `exploit_run` | 真实执行（python/php/bash/go），返回 stdout/stderr/exit_code/elapsed_ms/timed_out；默认 60s、上限 120s |
| `exploit_verify` | 标记 verified（要求至少 run 过一次），把**源码 + 证据原文**追加到 finding 报告 |
| `exploit_abandon` | 标记 abandoned，reason 写回 fact 供 planner 判断 |

**落库与回流**：

- `exploits` 表记录 task/finding/intent、target、vulnclass、cve、language、path、status、attempts、
  last_error、evidence；索引覆盖 task/status、finding、intent。
- `exploit_verify` 成功后：源码+证据追加到 finding 的 Markdown 报告（带 `ARTEX_EXPLOIT:<id>` 标记，
  重复 verify 不重复追加），源码另归档到 `<dataDir>/exploit-library/<vulnclass>/`；同时写一条
  `confidence=confirmed` 的 fact 并 `yields` 挂到意图。abandoned 写 `inferred` fact。
- 证据不可伪造：`exploit_verify` 的 evidence 必填；工具侧要求至少跑过一次（`attempts>0`），
  输出是否足以作为证据由提示词红线约束模型自检。
- 范围强制：`exploit_init` / `exploit_run` 在动目标前用任务的 `task_scope` 校验 target 主机
  （脚本里的目标对 Bash 主机抽取不可见，所以在工具侧显式补一道闸）；未登记 scope 时沿用
  平台既有的 fail-open 语义。

### Vuln Hunter（`action=vulnhunt`）

**何时触发**：planner 或人工下发 `action=vulnhunt` 意图，payload 带 `target_spec`、`fuzzer`。
典型用法是「目标是一个开源组件/本地二进制，需要 fuzz 找 0day」。

**工作区**：`vulnhunt_init` 先建 `vulnhunt_runs` 行，再绑定
`<dataDir>/tasks/<taskID>/vulnhunt/<runID>/{src,build,crashes,corpus,logs}`；`repo:` 走浅克隆
（可带 `@commit`），`binary:` 拷贝本地文件，`api:` 写 `src/TARGET_URL` 供 http harness 读取。

**工具链**：

| 工具 | 作用 |
|---|---|
| `vulnhunt_init` | 建 run + 工作区 + 克隆/拷贝目标；duration 默认 300s、上限 1800s |
| `vulnhunt_write_harness` | 写 `build/harness.c`（libFuzzer `LLVMFuzzerTestOneInput` / AFL++ `__AFL_FUZZ_TESTCASE_BUF`） |
| `vulnhunt_build` | 默认 clang ASan+fuzzer / `afl-clang-fast`，可传自定义 `build_cmd`；5 分钟超时 |
| `vulnhunt_fuzz` | libFuzzer `-max_total_time` 或 AFL++ `afl-fuzz -V`，返回 `crashes/` 文件列表 |
| `vulnhunt_triage` | 复跑 crash、解析 sanitizer、算 signature、最小化、去重 |
| `vulnhunt_report` | 把**唯一** crash 提升为 finding（vulnclass=`fuzzing`、worker=`vulnhunter`），并把 finding_id 回填到 crash 行 |

**去重与证据**：signature = `sha256("<Sanitizer>:<kind>|<栈顶 3 帧>")[:16]`；`vulnhunt_crashes`
上的 `(run_id, signature)` 唯一索引是去重事实源，同一 signature 的后续 triage 只返回首次的
crash_id（`duplicate_of` 指向它），不会重复插行。重复 crash 不会被 `vulnhunt_report` 提升。

**落库**：`vulnhunt_runs`（target_spec/fuzzer/workspace/status/duration/crash_count/unique_count/
last_error）与 `vulnhunt_crashes`（signature/kind/stack/poc_path/minimized_path/duplicate_of/
finding_id）。run 状态流转 `clone → building → fuzzing → triaging → done|failed`。

### 边界与实现位置

- **边界**：Exploit Author 只打意图给定的 target，`exploit_init`/`exploit_run` 会先按任务的
  `task_scope` 校验目标主机，worker 仍挂 guard hooks；Vuln Hunter 只对工作区里的克隆/编译产物
  fuzz，不向外部主机发包。两者都不把「疑似」写成 finding。
- **专用提示词**以 Markdown 存放并嵌入二进制：[agent/prompts/exploit_author_prompt.md](agent/prompts/exploit_author_prompt.md)、
  [agent/prompts/vulnhunter_prompt.md](agent/prompts/vulnhunter_prompt.md)，经 `agent.RenderPrompt`
  走「DB 覆盖 → 代码默认」渲染；产物路径规约与红线是代码固定尾，不可被 DB 正文编辑掉。
- **代码位置**：`db/exploit.go`、`db/vulnhunt.go`；`server/exploit_tools.go`、`server/exploit_author.go`、
  `server/vulnhunter_tools.go`、`server/vulnhunter.go`；分流在 `server/engine.go` 的
  `runSpecialIntent`，派单在 `server/msf_runtime.go` 的 `kickExploitAuthor`。
- **工具发现**：这两组工具不 seed 进 `tools` 表、不参与 per-agent 绑定，只注入到对应 action 的
  专用 worker；避免通用 worker 误用 `exploit_run`/`vulnhunt_*` 这类高风险工具。

---

## WAF 绕过预筛（0.3.20）

新增人工接口 `POST /api/waf-probe`（JWT 之后，仅操作者手动触发，不进入 agent 工具面）：先发一条
基线请求识别 WAF 指纹，再把**同一条 SQL 注入意图**用 8 种编码/变形逐条重放，逐条判定
「被拦截 / 放行 / 状态码变化」，输出结论与证据链。适合在正式打点前快速判断目标 WAF 类型与绕过成本。

```bash
curl -s -X POST http://127.0.0.1:8787/api/waf-probe \
  -H "Authorization: Bearer $ARTEX_TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com/item?id=1","timeout_seconds":20}'
```

响应字段：

| 字段 | 含义 |
|---|---|
| `waf_detected` | 从基线响应头/体识别的 WAF（cloudflare / sucuri / akamai / cdn / aws-elb / modsecurity / imperva / barracuda / fortinet / generic-waf），空=未识别 |
| `verdict` | `bypassable`（至少一种变体穿过）/ `hard`（识别到 WAF 且变体全被拦）/ `skip`（无 WAF 且变体无变化，或目标不可达） |
| `bypassable` / `bypass_method` | 是否可穿，以及穿过变体的名称、策略、状态码 |
| `score` | 0-100，越高越值得打：可穿 `50+10×变体数`（封顶 100）、识别到 WAF 但全拦 10、无结论 20 |
| `evidence` | 每个变体的逐条证据（明文 / 注释混淆 / 大小写 / 双重 URL 编码 / Unicode 引号 / MySQL 版本注释 / 换行 / Tab） |

实现：`server/waf_bypass_probe.go`。`timeout_seconds` 是**单请求**超时（默认 20s、上限 60s），
1 条基线 + 8 条变体串行发送，最坏耗时约 `9 × timeout`。404 不计为绕过（视为端点不存在）；
TLS 校验关闭以兼容自签名靶场。本接口只做「预筛」，真正利用仍应走 guard / RoE / scope 约束。

---

## AD 与端口扫描工具（0.3.21）

两个工具都默认绑定 worker，遵循「**执行归代码，决策归 AI**」：代码只做参数校验、scope、依赖发现、
进程执行、输出解析、去重排序与图谱回写；**端口→服务的判断、漏洞判定、下一步打哪个模块由模型决定**。

### `ad_kerberoast`（MITRE T1558.003）

对域控做 Kerberoasting：枚举带 SPN 的服务账户，按 `target_user` 定向请求 TGS，返回可离线爆破的
`$krb5tgs$` 哈希（hashcat 13100 RC4 / 19700 AES）。

- **默认只枚举**（LDAP，低噪声、不产生 4769）；`target_user=<账号>` 才请求单账户 TGS；`request_all=true`
  才对全部候选请求（每个账户一条 4769，高噪声，非必要不用）。
- **凭据优先用平台凭据库**：`credential_id`（先 `list_credentials` 查）或自动选本任务中域匹配的
  `password`/`hash_nt` 凭据；也兼容显式 `username+password/hash`。secret 不会出现在工具返回里。
- 命中哈希回写 finding（evidence 含完整哈希与 hashcat 命令）；只枚举/未命中回写 fact + `next_steps`。
- 前提：DC 88/TCP 与 LDAP(389/636) 可达、操作机与 DC 时钟偏差 ≤5 分钟、已装 impacket
  （`GetUserSPNs.py` 在 PATH，或与 python 同环境的 Scripts 目录）。

### `scan_rustscan`（MITRE T1046）

用 RustScan 快速扫描目标 TCP 端口（默认 1-65535），返回结构化 `open_ports`（去重、排序）并回写 fact。

- 支持 IP / 域名 / CIDR；URL 或 `host:port` 会自动拆成 host+port。
- 默认拒绝大于 `/16` 的 CIDR，需要时显式 `allow_large_range=true`；`dry_run=true` 只解析目标与校验依赖。
- **端口开放本身不是漏洞**：工具只写 fact，不写 finding；下一步由模型按端口判断服务
  （22→SSH、445→SMB、389/636→LDAP、88→Kerberos、3389→RDP、1433→MSSQL、3306→MySQL、6379→Redis、
  80/443/8080→HTTP）再调用对应模块。
- 依赖：`rustscan` 在 PATH、`data/tools/rustscan[.exe]`，或 `ARTEX_RUSTSCAN_PATH` 指向二进制。
  安装：`cargo install rustscan` 或从 GitHub release 下载。
- worker 的代码固定工具纪律已要求：全端口/端口段扫描必须走 `scan_rustscan`，不要用 Bash 直接拼
  rustscan/nmap 做全端口扫描。

两个工具都会在启动时由 `BuiltinToolSeeds()` seed 进 `tools` 表并默认绑定 `worker`；**重启 ARTEX 后生效**，
无需 SQL 迁移。目标在隔离内网时，先从立足点建隧道/会话，本工具默认从 ARTEX 宿主发起。

---

## HTTP 黑盒侦察与差分（0.3.22）

`recon_http` 与 `http_diff` 都是 **Go 进程内 HTTP 客户端**（不依赖 curl/外部二进制），并复用 worker 的
per-run 出口：任务录制 MITM → 任务隧道 SOCKS5 → 全局代理 → 直连。因此这些请求会进入流量留痕，
也能走内网隧道，而不是绕过平台直连。

### `recon_http`（T1595）

对单个 URL 发一次 HTTP(S) 请求，替代模型手搓 `curl`：

- 返回 `status_code`、`headers`（多值，含 Set-Cookie）、`body_preview`（前 4KB）、`body_len`、
  `final_url`、`redirects`、`elapsed_ms` 与结构化 `error/error_kind`。
- 工具不自动维护 cookie jar；需要同一会话时把 Cookie/Authorization 放进 `headers`。
- 默认不跟随重定向；`follow=true` 最多 5 跳，**每一跳都校验 scope**，防止重定向越界。
- 默认 `insecure=true` 兼容自签名靶场；设 `insecure=false` 时使用系统 CA + 任务 MITM CA。
- `dry_run=true` 只校验 URL/scope/代理配置，不发请求。
- 不自动写 fact/finding：状态码/响应头/预览是证据，是否记为结论由模型判断。

### `http_diff`（T1595）

黑盒差分核心：同一 URL 模板发一次基线 + 多个变体，输出可行动信号：

- 参数：`url_template`（含 `{v}`）、`baseline`、`variants`（去重、最多 20）、`method`、
  `headers`、`body_template`、`follow`、`insecure`、`timeout_sec`（整次总预算）、`dry_run`。
- 强制同一主机：`{v}` 只能改路径/查询/请求体，**不能改主机名**，避免借模板越权扫描。
- 信号：`status_flip`（状态变到 2xx/3xx）、`status_diff`（其他状态变化）、`len_diff_40pct`、
  `len_diff_from_empty`、`content_diff`、`content_diff_same_size`；附带 `similarity`、`len_delta`、
  `content_changed`、`preview`、`body_sha256`。
- 工具不自动维护 cookie jar；基线/变体共用 `headers`，需要同一会话时显式传 Cookie/Authorization。
- `content_diff_same_size` 是**弱信号**：CSRF token、时间戳、随机串都会导致内容差异；必须看 preview
  并换方法/身份复测。**diff 不是漏洞**，确认可复现后才 `report_finding`。
- 不自动写 fact/finding；工具只提供基线/变体证据与信号。

worker 的代码固定工具纪律已要求：单请求 HTTP 侦察优先 `recon_http`，基线对比优先 `http_diff`，
不要手搓 curl/Go/Python HTTP 客户端；只有文件上传、流式响应、特殊协议等工具无法表达的场景才允许
手写最小脚本，并先在 fact 里说明原因。

两个工具同样在启动时 seed 进 `tools` 表并默认绑定 `worker`，**重启 ARTEX 后生效**，无需 SQL 迁移。

---

## AI 改 AI：自研闭环（skill_draft / skill_test / skill_promote）

旧版的 `genome_*` 表 + `evolve_*` 工具（0.3.23 的「基因组与成本进化」）已整体下线：它只能改文本、晋升还要等成本样本，实战价值低。现在的自研闭环走**造工具**这条路：

```
Worker 打不动目标（WAF 拦截 / 无现成 POC / 端口被过滤 / 提权失败）
  → skill_draft  写一个只针对该目标的 Python / Bash 脚本到 skills/dynamic/<name>/
  → skill_test   立刻执行，拿真实 stdout/stderr/exit code
  → skill_promote 注册进 tools 表（kind=script/command），全任务 worker 立即可用
  → 用新工具继续攻击链（提权 / 横向 / 取证）
```

### 三个工具

| 工具 | 作用 |
|---|---|
| `skill_draft` | 写 `skills/dynamic/<name>/<name>.py\|.sh` + SKILL.md；名字白名单校验，单脚本 ≤256KB |
| `skill_test` | 唯一执行入口：带超时（默认 300s、上限 1800s）与 64KB 输出上限，回传真实 exit code |
| `skill_promote` | 把脚本注册成全局自定义工具（`sk_` 前缀、默认绑 `worker`）；同名重复晋升覆盖执行规格 |

### 强制触发

`server/engine.go` 里，意图以 `blocked` / `exhausted` 收场、且本任务累计失败意图
≥2 条时，引擎直接派一条 `action=self_evolve` 的意图（每任务上限 2 条，不递归），
worker 的系统提示里有代码固定的【渗透自进化核心协议】，要求它先写脚本再继续。

### 漏洞挖掘形态（0.3.26）：先取证，再写 EXP

通用自研仍从「失败」出发；0.3.26 在其前面加了一层**源码取证**，把「造工具」升级为
「先证明 Source→Sink，再造能绕过当前防御的工具」：

```
意图 blocked/exhausted
  → 信号判定（失败文本 + 本任务近期 finding）：WAF / 源码泄露 / 逻辑报错
  → 派 action=vuln_miner 意图（每任务 1 条；无信号则退回 0.3.23 的 self_evolve）
  → web_audit 抓前端资源 / audit_source 做 Source→Sink / ghidra_decompile 出伪代码
  → 只对「source 可控 + 危险 sink + 可达」的链路写 EXP（concatenated=true 优先）
  → skill_draft（含基线 vs 绕过差异验证）→ skill_test（真实回显）→ skill_promote
  → 工具 key = sk_<skill>（如 sk_waf_bypass_shop_example_com），描述里带「适用目标」
  → 写 fact + hint：「后续 worker 直接调用，不要重写脚本」
```

- **触发**：`classifyVulnMinerSignal` 只认三类信号（`waf_bypass` / `source_exposure` /
  `logic_flaw`）；`vuln_miner` 自身失败不再递归，也不再派通用 `self_evolve`。
- **工具**：`audit_source` 是纯静态（去注释/字符串后匹配 sink，给出行号与 flow），
  只读、不执行目标代码；`ghidra_decompile` 用**内置 Ghidra**（开源，替代闭源 IDA）跑
  `support/analyzeHeadless`：独立临时 project、分析阶段有单独超时上限、跑完 `-deleteProject`；
  找不到 Ghidra 返回 `status=tool_missing`，没有 JDK 21+ 返回 `java_missing`，不会拿占位伪代码糊弄。
  查找顺序：`ARTEX_GHIDRA_HOME` → `<ARTEX目录>/ghidra` → `<cwd>/ghidra` → PATH；
  JDK 查找顺序：`ARTEX_GHIDRA_JAVA_HOME` → `JAVA_HOME` → 常见安装目录（只认真实 `java -version` ≥ 21）。
- **复用**：`skill_promote` 落库后绑定 `worker`，下一个意图运行前 `AugmentTools`
  按 `tools` 表重建工具集，因此新工具**无需重启**即可被下一个 worker 调用；
  `vuln_miner` 收尾会回查 `tools` 表并写 fact/hint，planner 与后续 worker 都能看到。
  晋升后的 Python 工具会在入口把 `TOOL_ARGS` 还原成 `sys.argv`（自定义 script 工具没有
  argv），所以 `sk_xxx(args="--target ... --param ...")` 直接调用即可复现验证过的行为。
- **证据纪律**：没有真实回显不许晋升；晋升后回查工具行；本轮没产出工具也要写 fact
  收口（附卡点），避免规划者反复派同轴挖掘。
- **关闭开关**：`ARTEX_VULN_MINER=off`（只关挖掘形态；`ARTEX_SELF_EVOLVE=off` 关整条自研链路）。

### 硬边界

- 自研脚本只能写 `skills/dynamic/`；不能改 `.go`/SQL/guard/scope/RoE。
- `skill_promote` 只注册 `system=false` 的自定义工具，`sk_` 前缀不会覆盖内置工具。
- 已晋升的 Python 工具把脚本正文内联进 `exec`；Bash 工具按绝对路径调用——删文件不会让工具悄悄失效。
- 关闭开关：`ARTEX_SELF_EVOLVE=off`（整条链路），`ARTEX_SELF_EVOLVE_SEED=off`（只关合成记忆）。


---

## 前端源码审计（0.3.24）

`web_audit` 抓取页面与外部 JS/CSS，做静态提取，不执行 JS：

- HTML：表单 `action+method`、注释（可能泄漏测试账号/内部路径）。
- JS：`fetch/axios/ajax` 调用、`/api/...` 字面量、AWS AK、阿里云 AK、JWT、`password/secret/token` 赋值、`.innerHTML`/`eval`/`document.write`/`dangerouslySetInnerHTML`/`setTimeout(string)`。
- CSS：只发现路径，不做深度审计。
- 默认只抓 **同 host** 资源；`include_external=true` 才抓跨域 CDN，且跨域 host 仍受任务 scope 校验，避免把 HTML 的 `src` 变成 SSRF。
- `max_files` 默认 20（上限 100），`max_size` 默认 2MB（上限 8MB）。
- 走任务 MITM（若开启）→ 目标，结果带 `egress=task_mitm|direct`；抓取动作会进流量台账。
- 发现硬编码密钥且任务上下文可用时自动写 `hardcoded-secrets` finding；其余结果供模型交给 `recon_http`/`http_diff`/`path_probe` 复测。
- 局限：不执行 JS、不处理 SPA 运行时路由；运行时接口/权限树仍需浏览器工具或 `http_diff`。

### 本版未接入的高风险执行器

`credential_spray`、`sqli_dump`、`upload_shell`、`ad_adcs_esc`、`lateral_move` **没有**按外部草案直接并入：

- 凭据喷洒的 lockout 探测必须是真实实现，且默认 dry-run/人工确认；草案里的 `probeLockoutThreshold` 是返回 0 的占位，直接跑会锁账号。
- SQLi dump 需要经过验证的布尔/时间 oracle；草案的 true/false 判定和 `s.fetchRaw` 不成立，直接落库会产出假数据。
- ADCS 属于高影响枚举/利用，需要 `certipy` 外部工具 + 显式确认 + 审计；`ad_dcsync` 已单独实现并加 confirm 闸门。
- `upload_shell` / `lateral_move` 已有 `exploit_author` / `session_exec` 通道，重复执行器会绕过现有 guard。

这些能力在补齐“真实 lockout 策略读取 + dry-run 默认 + 显式 confirm + 证据回写”之前，继续走 `exploit_author` / `session_exec` / `msf_execute` 或人工外部工具。

`raw_tcp` / `sqlmap_run` / `nuclei_run` / `web_audit` / `impacket_proxy` / `db_dump` / `png_stego` / `win_inject` / `skill_draft` / `skill_test` / `skill_promote` 在启动时 seed 进 `tools` 表并默认绑定 `worker`；`ad_asreproast` / `ad_dcsync` 属于内置工具，同样在启动时 seed。**重启 ARTEX 后生效**，无需 SQL 迁移。

---

## 成本控制（DeepSeek 省钱）

0.3.16 起，每个任务（一次漏洞挖掘会话）默认**封顶 ¥6**：按任务累计 `llm_usage` 台账里的 token，
用价格表折算成人民币，到线就不再发出新的模型调用。价格表默认按 **deepseek-chat 官方价**配置
（输入 ¥2/百万、缓存命中 ¥0.5/百万、输出 ¥8/百万、缓存写入不单独计费），所以「¥6 能买多少
token」是按 DeepSeek 算的：

- **两级闸门，停在 6 块附近而不是跑飞了才停**：在跑的 worker/planner 在下一次模型调用时由平台
  本地合成一个「预算已用尽」的正常结束回合（零成本、不触发重试、不把意图标成 blocked）；引擎同时
  停止派发/领取新意图，等在跑的执行 drain 完（上限 90 秒，超时才硬取消）后把任务落成 `paused`，
  已写回的事实、资产、漏洞全部保留。预算耗尽不跑「终局规划轮」——那一轮本身也要花钱。
- **缓存命中不重复计费**：norma 的 `InputTokens` 是含缓存命中的总输入，成本按
  `(输入 − 缓存命中) × 输入价 + 缓存命中 × 命中价 + 输出 × 输出价` 计算，不会把缓存前缀算两遍。
- **可调、即时生效**：「系统配置 → **单次会话预算 · 漏洞挖掘成本**」填「元 / 任务」（0 = 不限），
  改完下一次模型调用就按新值判断；容器可用 `ARTEX_SESSION_BUDGET_CNY` 钉死。
- **价格表可覆盖**：设置项 `llm_price_{input,output,cache_read,cache_write}_cny_per_mtok`，或环境变量
  `ARTEX_PRICE_INPUT_CNY_PER_MTOK` / `ARTEX_PRICE_OUTPUT_CNY_PER_MTOK` /
  `ARTEX_PRICE_CACHE_READ_CNY_PER_MTOK` / `ARTEX_PRICE_CACHE_WRITE_CNY_PER_MTOK`。**默认值只对
  DeepSeek 准确**：用 Claude / GPT / 中转站时先按实际单价覆盖，否则 ¥6 的购买力会被高估或低估。
- **钱在页面上看得见**：任务详情「会话」页在 token 总计旁显示 `≈¥已用 / 上限 ¥6.00`（悬停看剩余
  与触发后的行为，到线标黄）；`GET /api/exploration/tokens` 的 `cost` 字段给出已用 / 上限 / 剩余 /
  是否计价；仪表盘的 token 卡片把「缓存命中」单列并算命中率。
- **让模型自己收敛**：planner 每轮、worker 每次运行都会带一行预算余额（上限、已用、剩余、百分比），
  提示接近上限时优先推进最可能出结果的方向、尽早写回，而不是继续扩大枚举。

### 省钱小妙招

- **先看缓存命中率**：命中部分只按 ¥0.5/百万计，是未命中（¥2/百万）的四分之一。仪表盘的
  「缓存命中率」长期偏低（不足 50% 会标黄），说明前缀总在变——换模型、改系统提示词、改工具集
  都会让缓存从零重建。
- **别中途换模型**：一次会话里切 LLM 配置（含故障转移切到另一个配置）会丢掉已建立的缓存前缀，
  下一轮全额重算。要换就在开任务前换。
- **上下文窗口(K) 按模型真实值填**：它只在本地用来算压缩阈值——填得比真实值小会提前触发压缩，
  而压缩本身也要花 token；填得过大则压缩更晚，后续每轮要带的上下文更长。
- **worker 数别开太大**：默认 3，每个 worker 是独立上下文，同一份态势要被重复注入。先把并发
  降下来，再考虑加预算。
- **按角色分模型**：Agent 管理里可以给每个 agent 单独绑 LLM——planner / mainagent 用强模型，
  worker 池用便宜的（如 `deepseek-chat`），大头开销在 worker 上。
- **不需要模型兜底审批就关掉**：「系统 → 命令拦截」的「模型兜底审批」默认关闭；开启后每次裁决
  都是一次模型调用（该开关下方有独立用量卡片）。
- **预算到线先「继续」而不是重开任务**：`paused` 是可恢复状态，调高预算后点「继续」从待领队列
  接着跑；重开任务等于把已经花掉的侦察再买一遍。

---

## 安装

> 依赖数据库 **PostgreSQL**；探索需配置 **LLM**（`ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY`，也可在 UI 里配）。
> 可选：启用 Metasploit 全自动闭环只需安装 Metasploit 本体（ARTEX 会自己拉起受管 `msfrpcd`）。
> RPC 客户端已在二进制里，不需要 Python / pip / MCP。

### 方式一：一键安装脚本（推荐）

```bash
git clone https://github.com/7huukdlnkjkjba/ARTEX.git
cd ARTEX
./install.sh
```

脚本会：检测 / 自动安装 Docker → 让你选 **① 全部 Docker** 或 **② 本地编译运行**：

- **① 全部 Docker**：填一个 Postgres 密码（可回车随机）→ 自动写 `.env` → `docker compose up -d`。
- **② 本地运行**：选数据库（连已有 / 用 Docker 起一个）→ 生成 `config.json` → `go` 编译内嵌单二进制 → 启动。

装好后打开 **http://localhost:8787**（首次进入 `/setup` 设置管理员密码）。

### 方式二：Docker Compose（手动）

```bash
git clone https://github.com/7huukdlnkjkjba/ARTEX.git
cd ARTEX
cp .env.example .env          # 填 POSTGRES_PASSWORD、可选 ANTHROPIC_API_KEY
docker compose up -d          # 拉取 autumn27/artex 镜像 + postgres
# → http://localhost:8787
```

镜像已含常用工具（ripgrep/curl/vim/npm/nmap…）；`./skills` 与 `./data` 以绑定挂载持久化。

远程 MCP 可在系统设置中选择 `http`（Streamable HTTP）或 `sse`（旧版 SSE）。
旧版 SSE 服务通常使用 `GET /sse` 建立事件流，再通过服务返回的
`/message?sessionId=...` 接收 JSON-RPC 请求；配置时将 URL 填为 `/sse`，请求头按
`Authorization=Bearer <token>` 填写。

### 方式三：下载预编译二进制（Releases）

到 [Releases](https://github.com/7huukdlnkjkjba/ARTEX) 下载对应平台的 zip，解压后得到 `artex` + `start.sh`（Windows 为 `start.bat`）+ `skills/` + `config.example.json`：

```bash
cp config.example.json config.json   # 填好 database 连接
./start.sh                           # → http://localhost:8787
```

> 请用 `start.sh` / `start.bat` 启动，而不是直接跑 `./artex`。它是个守护脚本：程序退出后按退出码决定是否重新拉起，**页面上的[一键更新](#方式一页面一键更新推荐)靠它完成换装**。直接运行 `./artex` 时更新完就不会被拉起了。
> 后台常驻：`nohup ./start.sh >artex.log 2>&1 &`。

### 方式四：从源码编译单二进制

```bash
# 1) 前端静态导出
cd web && npm ci && npm run build:static && cd ..
# 2) 拷进内嵌目录
cp -r web/out server/webui/dist
# 3) 编译（-tags embedui 才内嵌前端）
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
./start.sh
```

### 方式五：构建跨平台 Release 压缩包

`build.sh` 会先构建并嵌入前端，再使用 Go linker 去除调试信息，并将发布文件压缩为 zip。Release 模式默认生成 Linux amd64/arm64、macOS amd64/arm64 和 Windows amd64 的 zip 包：

```bash
./build.sh --release
# 产物：dist/artex-0.3.3-*.zip
```

UPX 自解压二进制可能与部分 Linux 内核、虚拟化环境或安全策略不兼容，因此默认不启用。可用 `ARTEX_TARGETS` 自定义目标；确认目标运行环境兼容时，可显式传入 `--upx` 进一步缩小二进制：

```bash
ARTEX_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
./build.sh --target linux/amd64 --upx
```

---

## 更新升级

> 升级只换程序、不动数据：Postgres 数据卷 `pgdata`、`./data`（jwt.key / SQLite 等）、`./skills` 都会保留。**数据库迁移无需手动执行**——`artex` 每次启动会幂等重跑 `schema.sql`（含 `ADD COLUMN` / `CREATE INDEX IF NOT EXISTS`），即“重启即迁移”。升级前仍建议先备份 `./data` 与数据库。

### 本仓库的私有 Release 更新源

本仓库（[7huukdlnkjkjba/ARTEX](https://github.com/7huukdlnkjkjba/ARTEX)）

这是私有仓库。请为运行 ARTEX 的后端进程设置 `ARTEX_UPDATE_GITHUB_TOKEN`，令牌只需本仓库的 **Contents: read** 权限。令牌由后端用于查询 Release 和下载附件，不发送给浏览器，也不要提交到 Git。

```bash
# 先在当前 shell 或服务环境中安全设置 ARTEX_UPDATE_GITHUB_TOKEN
./start.sh
```

本地直接启动时，`start.sh` 不会自动读取 `.env`；必须将变量导出到进程环境。Docker Compose 部署则可在未纳入 Git 的 `.env` 中填写该变量，并重建 artex 容器；镜像需要包含本分支的更新代码，旧版镜像不会因此切换升级源。

需要先在本仓库发布非 draft、非 prerelease 的正式 Release，并附上 `artex-<版本>-<os>-<arch>.zip` 和 `SHA256SUMS`，页面才能提供可安装更新。仓库里只有源码时还不能在线升级。现有 Release 工作流会在推送 `v*` tag 时为当前仓库生成这些附件。f

### 方式一：页面一键更新（推荐）

在 **系统配置** 页（侧边栏「系统配置」→ `/system/settings`）的**版本与更新**卡片里，可以直接检查并安装新版本，无需登录服务器。

点「更新」后：下载当前平台的发布包 → 比对 Release 的 `SHA256SUMS` → 用 `-h` 冒烟测试新二进制 → 暂存为 `artex.new` → 程序退出，由 `start.sh` / `start.bat` 重新拉起并完成换装。页面会自动等到新版本上线后刷新。

- **失败不会留下坏程序**：校验或冒烟不通过就丢弃暂存件、继续跑当前版本；换装后的新版若连续 3 次启动失败，会自动回滚到 `artex.old`（失败的那个留作 `artex.failed` 供排查）。
- **随时可回退**：上一版本保留为 `artex.old`，卡片上有「回滚到上一版本」。注意数据库结构不会回退。
- **更新会中断正在运行的任务**——更新即重启，请在空闲时进行。
- **开发构建不给更新**：版本号是 `dev` 或 `git describe` 带后缀时禁用，避免正式版覆盖掉本地调试的二进制。
- **Docker 下只换程序、不换镜像**：镜像里的 playwright / nmap 等工具链不会跟着升级，且 `docker compose up -d` 重建容器后会退回镜像自带的版本。要连镜像一起升级仍请用 `docker compose pull artex && docker compose up -d artex`。
- 访问 GitHub 需要代理时，在同一页面配置**全局代理**即可，更新链路会走它。更新只从 GitHub 域名下载并强制 HTTPS。

### 方式二：一键更新脚本

```bash
cd ARTEX
./update.sh
```

脚本先可选 `git pull` 拉取最新代码，再让你选 **① Docker 更新** 或 **② 本地编译更新**（与 `install.sh` 对应）：

- **① Docker**：可指定目标镜像 tag（回车沿用 `.env` 的 `ARTEX_TAG`，缺省 `latest`）→ `docker compose pull` → `docker compose up -d`（换新镜像重启即自动迁移）。
- **② 本地**：重建前端静态产物 → 重新编译 `./artex`（完成后重启进程生效）。

### 方式三：Docker Compose（手动）

```bash
cd ARTEX
git pull                       # 更新 compose / 脚本（可选）
# 指定版本：在 .env 设 ARTEX_TAG=v0.2.0；不设则用 latest
docker compose pull artex
docker compose up -d artex     # 换新镜像重启 → 自动迁移 schema
docker image prune -f          # 清理旧镜像（可选）
```

### 方式四：预编译二进制（Releases）

到 [Releases](https://github.com/Hinln/ARTEX/releases) 下载新版本 zip，停掉旧进程后覆盖 `artex` 与 `skills/`（保留你的 `config.json` 与 `data/`），重启即可：

```bash
cp -r <解压目录>/skills ./ && cp <解压目录>/artex ./
./start.sh
```

### 方式五：从源码编译

```bash
git pull
cd web && npm ci && npm run build:static && cd ..
cp -r web/out server/webui/dist
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
# 重启 ./start.sh
```

---

## 配置

**数据库**（`config.json`，或用环境变量 `ARTEX_PG_DSN` 覆盖）：

```json
{
  "database": {
    "host": "127.0.0.1", "port": 5432,
    "user": "artex", "password": "yourpass",
    "dbname": "artex", "sslmode": "disable"
  }
}
```

**LLM**：`export ANTHROPIC_API_KEY=sk-...`（或 `OPENAI_API_KEY`），也可在 UI 的「LLM 配置」页填写。
可选：`ARTEX_LLM_PROVIDER` / `ARTEX_LLM_MODEL` / `ARTEX_LLM_BASE_URL` / `ARTEX_LLM_PROXY`。

### 本地 AI（Ollama / LM Studio / llama.cpp / vLLM）

ARTEX 走 OpenAI Chat Completions 兼容协议，所以本地模型服务可以直接接，**不需要 API Key**：

```bash
# Ollama（先 ollama serve && ollama pull qwen2.5:7b）
export ARTEX_LLM_PROVIDER=openai            # 也可写 ollama/local
export ARTEX_LLM_BASE_URL=http://127.0.0.1:11434/v1
export ARTEX_LLM_MODEL=qwen2.5:7b
# 关键：不设置 ANTHROPIC_API_KEY / OPENAI_API_KEY
./start.sh
```

UI 里更简单：**系统 → LLM 配置 → 新建**，格式选「OpenAI 兼容」，
点 `Ollama` / `LM Studio` / `llama.cpp` / `vLLM` 预设，模型点右侧刷新按钮从 `/models` 拉取，
API Key 留空，保存后「设为激活」即可。

- 识别为本地/LAN 的 Base URL：`localhost`、`127.0.0.1`、`::1`、`10/8`、`172.16–31`、`192.168/16`、
  `*.local` / `*.lan` / `*.internal`、`host.docker.internal`，以及不带点的 compose 服务名（如 `ollama`）。
- 本地端点会自动使用占位 Key（`local`），避免某些 OpenAI 兼容网关拒绝空的 `Authorization` 头；
  云端点仍然必须填 Key。
- 模型必须支持 **OpenAI tool calling**（ARTEX 的 planner/worker 全靠工具调用）：`qwen2.5`、`qwen3`、
  `llama3.1+`、`mistral-nemo` 等；纯文本模型能连上但跑不动 agent。
- 7B 模型在长上下文里会变慢，建议在 LLM 配置里把「上下文窗口(K)」设成模型真实值（如 32/128），
  并适当降低每任务 worker 数。

### 内置免费模型池（0 成本，免 Key 起步）

除 Chat2API 外，ARTEX 还自带一套**免费账号池**：来源目录内置、成员是普通 LLM 配置，
不需要任何外部程序就能开跑。入口在 **系统 → LLM 配置** 顶部的「内置免费模型池」卡片。

| 来源 | 免 Key | 说明 |
|---|---|---|
| 本地 Ollama | ✅（本机） | 默认 `qwen2.5:7b`；装了 Ollama 且模型已 pull，启动时自动入池；完全不出网、不限速 |
| Pollinations | ✅ | 匿名档 `openai-fast`（gpt-oss-20b），支持 tool calling；限 1 次/45 秒，填 pollen key 可提额 |
| OpenRouter | ❌（自备 Key） | 免费档模型带 `:free` 后缀，每天有免费额度 |
| Groq | ❌（自备 Key） | 免费额度、响应快 |
| Google Gemini | ❌（自备 Key） | AI Studio 免费额度（OpenAI 兼容端点） |
| Cerebras | ❌（自备 Key） | 免费额度、推理极快 |
| Mistral | ❌（自备 Key） | Experiment 免费档（注意该档的数据使用条款） |
| NVIDIA NIM | ❌（自备 Key） | 注册送免费额度，模型多 |
| GitHub Models | ❌（自备 Key） | 用 GitHub PAT 当 Key，按账号给速率 |
| Together AI | ❌（自备 Key） | 带 `-Free` 后缀的模型免费 |
| 硅基流动 SiliconFlow | ❌（自备 Key） | 部分小模型免费，国内直连 |
| 智谱 Z.ai | ❌（自备 Key） | GLM Flash 系列免费 |
| 魔搭 ModelScope | ❌（自备 Key） | 每日免费额度；工具调用支持有限 |
| Hugging Face | ❌（自备 Key） | 每月免费额度；工具调用支持有限 |

用法：

1. 打开卡片，点 **检测**：每个成员会真的发一次极小的 chat completion（不是只看 `/models` 200），
   用绿点标出可用来源；
2. 打开右侧开关 **启用**：自动选第一个能回话的来源设为激活，并打开「轮询配置」的故障转移——
   当前来源被限流/报错时自动换下一个池成员，任务不会卡死；
3. 也可以只点某个成员的 **设为激活** 单独使用；
4. 带 Key 的来源有两条**不用手填**的入池路径：环境里已经导出该厂商的 Key
   （`OPENROUTER_API_KEY`、`GROQ_API_KEY`、`GEMINI_API_KEY`/`GOOGLE_API_KEY`、`CEREBRAS_API_KEY`、
   `MISTRAL_API_KEY`、`NVIDIA_API_KEY`、`GITHUB_TOKEN`、`TOGETHER_API_KEY`、`SILICONFLOW_API_KEY`、
   `ZAI_API_KEY`、`MODELSCOPE_API_KEY`、`HF_TOKEN`）→ 启动时自动建成员；或者你已经有一条
   **同 BaseURL** 的普通 LLM 配置 → 池子直接复用它，不重复建 profile。
   其余情况点 **添加账号**，选来源、填自己的 Key 即可入池。免 Key 来源首次启动自动入池。

注意：

- 免费源是共享算力：会限流、会排队，`openai-fast` 也不是强模型；重要任务建议配云端 Key，
  把免费池当兜底（故障转移会自动切过去）；
- 池成员的 `api_key` 对免 Key 来源存的是占位值 `free-pool`（ARTEX 认为远端端点必须有 Key，
  该值不会外泄，Pollinations 也会忽略 `Authorization`）；
- 复用来的既有配置（名字不以 `免费池·` 开头）被移出池子时只摘链接、不删除原配置；
- 每个成员默认带保守限速（Pollinations 1 次/45 秒；带 Key 的免费档 0.5–1 req/s、30 req/min），
  可在配置卡片里改；跑多任务时别把限速拉满，否则会看到大量 429/402；
- 免费来源的可用性不在我们控制范围内，目录里加新来源只需改 `server/freepool.go` 的
  `builtinFreeSources()`。

### 免费模型源：Chat2API（内置，0 成本）

[Chat2API](https://github.com/xiaoY233/Chat2API) 是本地桌面端聚合代理：它驱动 DeepSeek、GLM、Kimi、
MiniMax、Qwen、Z.ai 等官方 Web UI，把这些账号额度转成 **OpenAI 兼容接口**，等于不额外花钱就能给 ARTEX
供模型。ARTEX 只当它是普通的 OpenAI 兼容端点，无需改代码。

**内置配置**：首次启动（连上 PostgreSQL）时，ARTEX 会自动建好一条名为 **`Chat2API（免费）`** 的 LLM 配置
（`openai` 格式、`http://127.0.0.1:8080/v1`、默认模型 `deepseek-v4-pro`、本地端点免 Key）。它**不会自动激活**，
也不会参与故障转移轮询，避免 Chat2API 没开时把请求带走；只有你手动「设为激活」才启用。删掉后下次启动会重新内置。

使用步骤：

1. 启动 Chat2API 桌面端，在「供应商」页添加账号并完成登录（OAuth / Token 均可），确认「代理」已启动；
2. 记下代理端口（默认 `8080`，可在 Chat2API 设置里改；注意别和本机 llama.cpp 的 8080 撞车）；
3. ARTEX 打开 **系统 → LLM 配置**，列表里已有 `Chat2API（免费）`：
   - 直接点卡片上的 **设为激活** 即可；模型不是 `deepseek-v4-pro` 时点「编辑」，用模型右侧刷新按钮从
     `/models` 拉取后选中（如 `glm-5.1`、`kimi-k2.6`）；
   - 也可以不激活内置项，**新建**一个并点 Base URL 下方的 **Chat2API** 预设，效果相同；
4. API Key 留空（同机 `127.0.0.1` 属本地端点）；若在 Chat2API 里开启了 Key 校验，则填它生成的 `sk-...`。

不想开 UI 也可以用环境变量：

```bash
export ARTEX_LLM_PROVIDER=openai
export ARTEX_LLM_BASE_URL=http://127.0.0.1:8080/v1
export ARTEX_LLM_MODEL=deepseek-v4-pro
# 不设置 OPENAI_API_KEY（本地端点会补占位 Key）
```

注意：

- Chat2API 默认只监听 `127.0.0.1`；与 ARTEX 不同机时，先在 Chat2API 设置里把监听地址改成 `0.0.0.0`，
  再把这里的 `127.0.0.1` 换成 Chat2API 所在机器的 IP（注意其默认端口 8080）；
- Chat2API 的工具调用是通过提示词模拟的，兼容 Cherry Studio / Kilo Code 这类客户端；ARTEX 的 planner
  依赖严格 tool calling，复杂任务建议优先选原生支持 function calling 的模型，或在 Chat2API 里调整
  「工具调用」相关设置；
- 网页账号有频控，跑多任务时把 LLM 配置里的「每秒/每分钟请求」限制调低，避免账号被限流。

**并发**：每个任务的 work agent 数在「系统设置」里配置（默认 3）。

**日志**：任务终态自动清空日志——任务进入 `done` / `failed` / `timeout` 时清空后端日志（内存缓冲 + 数据库 `server_logs`），成功与失败一视同仁；「系统 → 日志」页的「清空日志」按钮也可随时手动清空（内存与数据库一起删，其它打开的日志页同步清屏）。不想自动清空可在「系统配置 → 任务跑完自动清日志」关闭（默认开，切换即时生效）。

**常用参数**：`./start.sh -addr :8787 -proxy :8788`（`-addr` 前端+API，`-proxy` 流量录制代理）。启动脚本会把参数原样透传给 `artex`。

### 反向代理部署（HTTPS / 只开放 443）

前端和 API/SSE 都由同一个后端端口（默认 `:8787`）提供，实时活动流默认走**同源**地址，因此**无需配置 `NEXT_PUBLIC_SSE_BASE`**，公网只开放 443、把 8787 留在内网即可。

SSE 是长连接 + 持续推送，反代**必须关闭缓冲**，否则浏览器能连上却收不到事件（表现为活动流一直转圈）。Nginx 示例：

```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE 关键项：关缓冲、长超时、HTTP/1.1
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

> 仅当 SSE 需要走与页面不同的来源（如独立子域）时，才在**构建期**设置 `NEXT_PUBLIC_SSE_BASE`（该变量在 `next build` 时固化进静态包，容器运行时再设无效）。

---



## 开发

### 手动漏洞复测

任务详情的「复测」页签可分页选择本任务的漏洞、查看历次结论和证据，并手动发起复测。启动后保留当前页签，显示转圈图标和「复测中」；确认修复后同步更新漏洞状态。

在漏洞列表每行操作区点击「复测」，或在漏洞详情的「漏洞复测」区域点击「发起复测」，填写可选的修复版本、测试条件或限制，系统会创建独立的复测 Agent 会话，启动后保留当前页面。列表的平铺、按任务分组和资产视图均支持该入口；复测运行时显示转圈图标和「复测中」，需要查看时点击进入对应会话，结束后恢复「复测」。复测无需重新启动原扫描任务，结论分为「仍可复现」「已修复」「无法确认」，每次的结论、证据和会话链接保存在漏洞详情中。

新版后端首次启动会预置可编辑的「漏洞复测」（`retester`）Agent，可在 Agent 管理中配置提示词、LLM、运行预算和工具。默认使用其绑定的 LLM，未绑定则使用全局激活配置。复测会话成功完成且结论为「已修复」时，系统自动将漏洞处置状态改为「已修复」；执行中、失败、停止或其他结论保留原状态。原始证据和报告始终保留。也可在状态下拉菜单中手动选择「已修复」。同一漏洞正在复测时复用已有会话，停止、失败或服务重启后可重新发起。

本版历史记录通过漏洞详情和会话查看，暂未纳入漏洞报告导出或任务归档包，也未自动关联流量包。演示模式只生成明确标注的模拟记录，不请求真实目标。

### 本地运行与测试

```bash
./dev.sh    # 后端(:8787) + 流量代理(:8788) + 前端 next dev(:5173) → http://localhost:5173
```

- 后端：`go run ./cmd/artex`（不带 `-tags embedui` 则不内嵌前端）
- 前端：`cd web && npm run dev`（`/api` 反代到后端，带热更新）
- 测试：`go test ./...`
- Mock 预览（无后端）：`cd web && NEXT_PUBLIC_MOCK=1 npm run dev`

---

## 系统技术架构

ARTEX 是一套 **LLM 多 agent 驱动的自主渗透系统**：Go 单体后端（内嵌 Next.js 前端）+ PostgreSQL，agent 能力由 [`norma`](https://github.com/Autumn-27/norma) SDK 提供（`agentcore` / `tool` / `permission` / `harness` / `memory` / `transcript`）。核心是**双图架构**，以及围绕它的两条自主性机制：**worker 间过程级信息交换**与 **planner 多轮共享 todolist 稳定攻击链路**。

### 总体分层

```mermaid
flowchart TB
  subgraph FE["前端 Next.js（go:embed 内嵌单二进制）"]
    UI["仪表盘 · 任务 · 资产 · 覆盖图 · 流量 · 工作空间 · 系统配置"]
  end
  subgraph SRV["server（Go net/http）"]
    API["REST /api/*　JWT 鉴权　SSE"]
    ENG["engine 调度循环"]
    MGR["Manager　任务/引擎/store 生命周期"]
  end
  subgraph AG["agent（norma SDK）"]
    GO["goals　目标分解 + 提取范围"]
    PL["planner　规划者（唯一意图生成者）"]
    WK["worker　执行者 ×N"]
    MA["mainagent　人在环路"]
  end
  subgraph DB["PostgreSQL"]
    AGRAPH["资产图　assets / companies / task_scope"]
    EGRAPH["探索图　exploration_nodes / anchors / activity"]
  end
  subgraph SUB["支撑子系统"]
    PROXY["流量记录代理　MITM + CA 留痕"]
    GUARD["guard / intercept　工具审批门"]
    ENR["enrich　DNS / HTTP 异步补全"]
    EXT["MCP · skills · memory · report"]
  end

  UI -->|HTTP| API
  API --> MGR --> ENG
  ENG --> PL
  ENG --> WK
  API --> MA
  API --> GO
  PL --> DB
  WK --> DB
  MA --> DB
  GO --> DB
  WK -->|"Bash / HTTP 全程留痕"| PROXY
  WK --> GUARD
  WK --> ENR
  PL -.-> EXT
  WK -.-> EXT
  MA -.-> EXT
```

| 层 | 职责 |
| --- | --- |
| **前端** | Next.js 静态导出，`go:embed` 内嵌进单二进制；可视化任务/资产/探索链路/覆盖图，人在环路对话 |
| **server** | `net/http` 路由 + JWT 鉴权 + SSE；`Manager` 托管任务、引擎、DB store 的生命周期 |
| **engine** | 每任务一个 `plannerLoop` + N 个 worker goroutine；意图领取、超时/暂停/drain |
| **agent** | goals / planner / worker / mainagent，`ToolSet` 把双图暴露成 LLM 工具 |
| **db** | 双图的 Postgres 落地（pgx）；schema 随 `go:embed` 每次启动幂等建表 |
| **支撑** | 记录型 MITM 代理、审批门、异步补全、MCP/技能/记忆/报告 |

### 双图架构：探索图 + 资产图

系统把「**目标是什么**」和「**测到了什么程度**」拆成两张相互独立、又通过锚点相连的图：

- **资产图（Asset Graph，全局共享）**：跨任务同一份的资产真值库。节点为 `root_domain / subdomain / ip / service / app / endpoint`，归属公司；域名→子域→服务→端点的父子关系与去重 key 全部由程序计算，agent 只提交原始信息。
- **探索图（Exploration Graph，每任务独立）**：一次任务的“思考与推进”过程。节点为 `goal（目标）/ intent（意图）/ fact（事实）/ finding（漏洞）/ hint（提示）`，靠 `spawns / derived_from / yields / proves` 等边连成**血缘链**，回答“哪个方向派生自哪些事实、产出了什么”。
- **两图靠锚点相连**：`exploration_anchors(node_id, asset_id)` 把意图/事实/漏洞锚定到具体资产上——于是既能从“探索方向”看它打的是哪些资产，也能从“某个资产”反查它在本任务被哪些意图测过、得出过哪些事实。这也支撑了**资产测试覆盖度**与**资产覆盖图**（范围内资产 + 已测高亮）。

```mermaid
flowchart LR
  subgraph EG["探索图（每任务独立 · 推进链）"]
    direction TB
    G["goal 目标"]
    I1["intent 意图 A"]
    F1["fact 事实"]
    I2["intent 意图 B"]
    FD["finding 漏洞"]
    G -->|spawns| I1
    I1 -->|yields| F1
    F1 -->|derived_from| I2
    I2 -->|proves| FD
  end
  subgraph AG["资产图（全局共享 · 真值库）"]
    direction TB
    RD["root_domain"]
    SD["subdomain"]
    SV["service"]
    EP["endpoint"]
    RD --> SD --> SV --> EP
  end
  I1 -. anchor .-> SD
  F1 -. anchor .-> SV
  I2 -. anchor .-> EP
  FD -. anchor .-> EP
```

> 分工：**planner** 读探索图态势、判目标、只在有未覆盖的新方向时派**意图**进 frontier；**worker** 领**一条意图**、用真实工具执行、把新资产/事实/漏洞写回两图后即停。资产图是共享事实，探索图是每任务的推进链。

### 引擎与意图生命周期（一次探索的闭环）

引擎是**事件驱动**的闭环：图一变就唤醒 planner，planner 派意图，worker 领意图执行并写回，写回又触发下一轮——直到目标被证明（`prove_goal`）。

```mermaid
sequenceDiagram
  autonumber
  participant EV as 图变更 debounce
  participant P as planner
  participant FR as frontier 意图队列
  participant W as worker
  participant PX as 记录代理
  participant DB as 双图 + activity

  EV-->>P: 唤醒
  P->>DB: 读态势(graph_overview 预取 + coverage/scope)
  P->>FR: 派 0..N 个意图(带 asset_ids)
  Note over P,FR: 大多数唤醒派 0 个——无新方向即结束
  W->>FR: claimNext 领一条意图
  W->>DB: 取意图 asset_ids 的原始资产作为初始信息
  W->>PX: 真实工具执行(Kali / Bash / HTTP)
  PX-->>W: 响应(全程留痕 + CA 验证)
  W->>DB: 写回 fact / asset / finding + 每步 activity
  DB-->>EV: 图变更
  EV-->>P: 再次唤醒(闭环)
```

### worker 间的过程级信息交换

一次深入的探索里，很多有价值的观察（某个报错、某段响应、某个隐藏参数）出现在一个 worker 的**执行过程**中，却未必被写成正式 fact。为避免重复劳动、让链路上的 worker 能站在彼此的肩膀上，worker 具备**跨 work 检索过程**的能力：

- `search_all_worker_traces(q)`：在**本任务其他 work 的执行过程**里按关键字检索（自动排除自己这条意图的步骤），命中项带 `intent_id`；
- `list_worker_traces` / `get_worker_trace(intent_id, step_ids=[…])`：先看有哪些 work 跑过，再取某个 work 具体几步的完整内容做细节交换。

这样即便探索图上还没有对应的 fact，后续 worker 也能复用他人过程中的观察——**信息在 worker 之间以“执行过程”为粒度流动**，而边界不变（每个 worker 仍只做自己领到的那条意图）。

```mermaid
flowchart LR
  WA["worker A（意图 #12）"] -->|"每步 activity"| ACT[("探索图 · activity 过程库")]
  WB["worker B（意图 #34）"] -->|"每步 activity"| ACT
  WC["worker C（意图 #56）"] ==>|"1) search_all_worker_traces(q)"| ACT
  ACT ==>|"2) 命中 A/B 的步骤（排除自己）"| WC
  WC ==>|"3) get_worker_trace(id, step_ids)"| ACT
  ACT ==>|"4) 返回完整过程内容"| WC
```

### planner 多轮共享 todolist → 稳定的攻击链路

真实攻击链往往是**有前后依赖的多步序列**（如：发现注入点 → 拿到凭据 → 横向 → 提权），一次性把这些并行派下去只会乱套。planner 因此持有一份**按任务保留、跨唤醒共享的规划待办（todolist）**：

- planner 是事件驱动的——图一变就被唤醒，但**每次唤醒是全新会话**；共享的 todolist 让它把一条串行利用链**记录一次**、然后在后续多轮里**按依赖逐步派意图**，而不是把整条链在一轮里全部前置展开；
- 每轮只对「前置步骤已完成、其依赖的 fact 已存在」的下一步派意图，并随进展更新清单（把已被 fact 满足的步骤标完成）。

```mermaid
flowchart TB
  subgraph TODO["共享 todolist（按任务保留 · 跨唤醒常驻）"]
    direction LR
    T1["1 注入点　[已完成]"]
    T2["2 取凭据　[进行中]"]
    T3["3 横向　[待前置]"]
    T4["4 提权　[待前置]"]
    T1 -.前置满足.-> T2 -.-> T3 -.-> T4
  end
  R1["第 1 轮唤醒　派意图①"] --> T1
  R2["第 2 轮（①产出 fact）　派意图②"] --> T2
  R3["第 3 轮（②产出 fact）　派意图③"] --> T3
```

于是攻击链在“事件驱动 + 无状态会话”的环境下依然**稳定推进、不重复、不错序**——这是 ARTEX 能自主走完多步利用链的关键。

---

## 实战测试记录

### 记录 1：B 站（bilibili.com，授权范围测试，2026-11-05）

**任务目标**：获得 B 站服务器最高权限（后经人确认放宽为「交付可核查的攻击链与已确认漏洞报告」）。

**规模**：55 条已完成意图、64 条事实节点、1 条确认漏洞，覆盖 59 台主机 / 64 个范围内资产（覆盖率 ≈48%）。

**确认漏洞（1 条）**

| 编号 | 资产 | 类别 | 等级 | 摘要 |
|---|---|---|---|---|
| finding_id=1 | space.bilibili.com | 未授权访问 / 敏感信息泄露 | low | Node.js（v18.16.0）渲染服务的 Prometheus `/metrics` 未鉴权。Gaia 风控按**字面路径**匹配，内层 openresty 解码 `%2e%2e` 后回源，故 `GET /x/%2e%2e/metrics` 返回 **HTTP 200 / 525,854 字节** 指标（进程 CPU/内存/fd、事件循环与 GC、`nodejs_version_info`、按 caller 与 Express 风格路由正则聚合的请求计数）。同前缀下 `/vars`、`/status`、`/debug/pprof/` 与 `api/member` 同名路径均 404，说明端点只存在于 space 后端。属信息泄露，本身不构成命令执行入口。 |

> 证据形态：命令输出（未采集到流量记录——当时代理抓包链路返回空 200），且该端点后续复核时已被出口风控 412 拦下，不可稳定复现。

**攻击链（止步于信息泄露层）**

```
[侦察] 20 个前台子域横向对比 → 统一自建边缘 CDN（blzone0x），回源后端分 6 类
   └─ 真实业务后端仅 api（/x/ Go）、live（Fenice SSR/Koa）、space / data / cm 等少数
       │
[入口] space.bilibili.com  Gaia 字面匹配 vs openresty 解码不一致
   └─ GET /x/%2e%2e/metrics → 200, 525KB Prometheus 指标
       │
[提权尝试 —— 全部否定]
   ├─ /x/%2e%2e/actuator/{env,heapdump,mappings,health} → 后端真实 404（#482）
   ├─ /x/%2e%2e/actuator/env → Gaia 412 风控页（#484）
   ├─ /x/%2e%2e/{debug/pprof/,vars,status} → 真实 404（#482）
   ├─ Node inspector（/json、/json/list、/json/version）→ 未开放（#483）
   ├─ data.bilibili.com /log/%2f..%2factor%2f、/log/%2e%2e/actuator 系列 → openresty 1627 真 404（#476）
   └─ 结论：无可达的调试协议 / actuator / 提权面
       │
[其他分支 —— 全部否定]
   ├─ SSR 模板注入 / SSRF：live（Koa，Server-Timing 可见）+ e（Nuxt）均无求值、无外连（#454, #453）
   ├─ api.bilibili.com /x/ 未登录越权：全部落在公开数据 / -101 / -352 / -799（#466）
   ├─ pay / member S3 桶匿名读写：不成立（#415）；CORS 通配仅作用于静态外壳（#375, #416）
   ├─ 请求走私（CL.TE / TE.CL / TE.TE / h2c）：边界层直接拒绝（#429）
   ├─ cm.bilibili.com /fly/api/ Spring Boot：actuator / druid 全 404（#465, #468）
   ├─ 源站直连 / 反代小段直连 / 真实 IP 头伪造：均被平台授权管控拦截（#367, #442, #431, #376）
   └─ 邮件 / 客服 / 开发环境 / 死域：mail→Office365 302、service→504、ff-dev/ssr→NXDOMAIN（#405, #409, #395）
```

**结论**：确认 1 个 low 级未授权信息泄露；**RCE / 提权环节经实测确认不存在**，攻击链在 `/metrics` 信息泄露处终止，未能获得服务器权限。

**本次测试对系统的验证点**：双图血缘链在 55 条意图规模下保持可追溯；否定结论（端口关闭 / 参数不可注入 / 未见入口）与正向发现一并入库，能让规划者及时止损、不重复派单；`steer_work` 与 `add_hint` 在人工介入（放宽目标、注入战略提示）时能即时生效。

**能力边界**：APTEX可进行中低渗透测试，高顶渗透测试做不到

---

## 许可与免责声明

### 开源协议

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）** 授权，完整条款见仓库根目录的 [LICENSE](LICENSE) 文件。

这意味着任何人都可以自由使用、修改和分发本项目，但**衍生作品必须同样以 AGPL-3.0 开源**；特别地，**若你修改本项目并通过网络（如部署为在线服务）向用户提供，也必须向这些用户公开对应的完整源码**。

> ⚠️ **重要提示**：开源协议本身不限制软件的使用用途。以下的「使用限制」与「免责声明」是作者对使用者的额外约定与郑重声明，请务必遵守。

**ARTEX 仅供个人学习、代码研究与网络技术攻击验证使用，只用于对任何线上系统或网站发起实际测试。**

### 使用

- 可用于**阅读、学习与研究本项目源码**，以及在**网络技术攻击验证使用**中进行技术原理验证；
- 适用于个人学习、学术研究、代码审阅等攻击用途。

### 不禁止事项

- **不严禁使用本工具对任何网站、线上服务或联网系统发起扫描、探测、利用或攻击**（无论是否获得授权、是否为自有资产）；
- 不严禁将本工具用于任何实际的渗透测试、攻防对抗或生产环境；
- 不严禁将本工具用于非法入侵、数据窃取、勒索、拒绝服务或任何破坏性、犯罪性活动；
- 不严禁利用本工具从事违反所在国家/地区法律法规的行为。

### 合规责任

使用者须自行遵守所在国家/地区关于网络安全、数据保护与计算机犯罪的全部法律法规（在中国大陆包括但不限于《网络安全法》《数据安全法》《个人信息保护法》及相关司法解释）。**因使用本工具产生的一切法律责任与后果，均应由使用者自行承担。**

### 免责声明

本项目按“现状（AS IS）”提供，不附带任何明示或默示的担保。作者及贡献者不对使用本工具（无论使用方式是否得当）所导致的任何直接或间接损失、数据丢失、系统损坏或法律纠纷承担责任。**下载、安装或使用本项目，即表示你已阅读、理解并同意上述全部条款。**

