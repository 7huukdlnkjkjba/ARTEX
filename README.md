<div align="center">

# ARTEX

AI 自主渗透测试系统（Go 后端 + Next.js 前端）

</div>

---

## 版本与近期更新

本仓库（[7huukdlnkjkjba/ARTEX](https://github.com/7huukdlnkjkjba/ARTEX)）在上游基础上持续二开：

| 版本 | 内容 |
|---|---|
| **v0.3.16** | **deepseek-hermes省钱代码（成本控制）**：单次会话默认 ¥6 封顶，缓存命中按 ¥0.5/M 单独计价、不与输入重复计费，预算余额写进 planner/worker 提示词逼模型收敛，任务详情显示 `≈¥已用 / 上限` |
| **v0.3.17** | 并入artex-ymh能力「外网突破 → 立足点 → 内网纵深」：webshell 会话、penelope 反弹、`session_recon`、suo5/chisel 隧道、内网拓扑、凭据库、待授权网段、任务移交、伪装门控、一键放行、RoE 三态、蜜罐识别、chains 技能、`artex doctor` |
| **v0.3.18** | Metasploit **全自动闭环**（**端到端已验证 2026-10-27**）：确定性决策层 `msf/`、`msf_plan`/`msf_next`/`msf_execute`、自动拉起受管 msfrpcd、内置 MCP 启动、确认后自动派单、会话自动取证并写回 fact；闭环依赖**自动安装**（首次启动检测不到 `mcp-pymetasploit3` 时自动 `pip install`，可关、可指定解释器） |

- 内网能力说明：[README-FORK.md](README-FORK.md)、`INTRANET-PIVOT-DESIGN.md`、`HONEYPOT-DETECTION-DESIGN.md`
- Metasploit 闭环：[MSF-CLOSED-LOOP.md](MSF-CLOSED-LOOP.md)
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

对接 [mcp-pymetasploit3](https://github.com/daedalus/mcp-pymetasploit3)（Metasploit RPC 的 MCP 封装）。

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
  `127.0.0.1:55553`；用 `pymetasploit3` 直连可看到同一会话
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

**零手工安装**：首次启动检测不到 `mcp-pymetasploit3` 时，ARTEX 会自动执行
`pip install "mcp-pymetasploit3[mcp]"`（后台执行，最长 5 分钟；`ARTEX_MSF_AUTO_INSTALL=0` 可关，
`ARTEX_MSF_PYTHON=/path/to/python` 可指定解释器/venv）。Metasploit 已安装时也无需手工启动 msfrpcd。
模块映射、分支语义与环境变量见 [MSF-CLOSED-LOOP.md](MSF-CLOSED-LOOP.md)，Windows 可用
[scripts/setup-msf-mcp.ps1](scripts/setup-msf-mcp.ps1) 做预检。

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
> 可选：启用 Metasploit 全自动闭环需 `pip install mcp-pymetasploit3`，并安装 Metasploit（ARTEX 会自己拉起受管 `msfrpcd`）。

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

到 [Releases](https://github.com/Hinln/ARTEX/releases) 下载对应平台的 zip，解压后得到 `artex` + `start.sh`（Windows 为 `start.bat`）+ `skills/` + `config.example.json`：

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

页面一键更新固定从 [Hinln/ARTEX Releases](https://github.com/Hinln/ARTEX/releases) 检查和下载版本。克隆或通过 Git 更新源码也使用 `Hinln/ARTEX`；原项目的 Go module 路径保持不变。

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
