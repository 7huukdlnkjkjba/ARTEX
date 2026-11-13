package agent

// 按意图生成“本意图推荐工具”提示。
//
// 提示词里放一张全局工具表,模型在具体一条意图上仍然可能想不起来(2026-11 的
// transcript 里,一条“下载 JS 并审计”的意图,模型先试 WebFetch、再手搓 curl,
// 全程没碰 web_audit / recon_http)。把路由缩小到“这条意图 + 这次真正可用的工具”,
// 紧贴意图块输出,命中率远高于尾部的长纪律文本。
//
// 约束:
//   - 只推荐本 agent 最终工具列表里存在的工具(不产生 dangling 提示);
//   - 每个工具带自己的说明,过滤掉某个工具时不会在别的工具说明里留下它的名字;
//   - 总共最多 maxHintTools 条,避免又变成一张大表;
//   - 纯代码生成,不依赖 DB,也不改动用户可编辑的提示词正文。

import (
	"encoding/json"
	"regexp"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

type hintedTool struct {
	name string
	why  string
}

type toolHintRule struct {
	zh    []string       // substring keywords (Chinese)
	en    *regexp.Regexp // word-boundary keywords (English), optional
	tools []hintedTool   // recommended tools, in priority order
}

// 顺序即优先级;同一工具重复出现只保留第一次。
var toolHintRules = []toolHintRule{
	{
		zh: []string{"前端", "源码", "脚本", "静态审计"},
		en: regexp.MustCompile(`(?i)\b(js|javascript|script|dom|source\s*code)\b`),
		tools: []hintedTool{
			{"web_audit", "抓页面+同域 JS 做静态审计(表单/注释/API 路由/硬编码密钥/DOM XSS sink)"},
			{"recon_http", "单请求看状态码/响应头/4KB 体预览;完整响应体用 traffic_get"},
		},
	},
	{
		zh: []string{"端口", "扫描", "全端口"},
		en: regexp.MustCompile(`(?i)\b(port|ports|scan|scanning|nmap|rustscan)\b`),
		tools: []hintedTool{
			{"scan_rustscan", "只回开放端口并写回资产,自动走任务代理/隧道"},
		},
	},
	{
		zh: []string{"注入"},
		en: regexp.MustCompile(`(?i)\b(sql|sqli|injection|injectable)\b`),
		tools: []hintedTool{
			{"sqlmap_run", "先 detect;dump 需 confirm=true 且指定 table"},
			{"http_diff", "基线/变体差分(IDOR/越权/注入/认证差异)"},
			{"recon_http", "单请求看状态码/响应头/体预览"},
		},
	},
	{
		zh: []string{"目录", "路径", "备份", "敏感", "泄露", "暴露", "遍历"},
		en: regexp.MustCompile(`(?i)\b(path|paths|dir|directory|backup|exposure|disclosure|enumeration)\b`),
		tools: []hintedTool{
			{"path_probe", "自带 soft-404 校准的敏感路径探测"},
			{"admin_surface", "管理面板/后台入口识别"},
		},
	},
	{
		zh: []string{"登录", "认证", "鉴权", "越权", "未授权", "会话", "令牌"},
		en: regexp.MustCompile(`(?i)\b(auth|authentication|authorization|idor|token|session|cookie|login)\b`),
		tools: []hintedTool{
			{"auth_probe", "端点鉴权三态(匿名/普通/高权)"},
			{"http_diff", "换身份/换参数的基线与变体差分"},
		},
	},
	{
		zh: []string{"指纹", "版本", "框架", "组件"},
		en: regexp.MustCompile(`(?i)\b(fingerprint|version|framework|waf|cdn|tech)\b`),
		tools: []hintedTool{
			{"fingerprint", "WAF/CDN/框架指纹,结果进观察台账"},
		},
	},
	{
		zh: []string{"后台", "管理", "面板", "控制台"},
		en: regexp.MustCompile(`(?i)\b(admin|admin\s*panel|console|dashboard)\b`),
		tools: []hintedTool{
			{"admin_surface", "管理面识别"},
			{"path_probe", "敏感路径探测"},
		},
	},
	{
		zh: []string{"域控", "域内", "凭据", "哈希", "票据"},
		en: regexp.MustCompile(`(?i)\b(ad|kerberos|kerberoast|asrep|spn|ldap|smb|dcsync|ntlm)\b`),
		tools: []hintedTool{
			{"ad_kerberoast", "枚举/请求 SPN 服务票据"},
			{"ad_asreproast", "DONT_REQ_PREAUTH 账号"},
			{"ad_dcsync", "需复制权限,显式 confirm=true、target_user=krbtgt"},
		},
	},
	{
		zh: []string{"内网", "横向", "隧道"},
		en: regexp.MustCompile(`(?i)\b(redis|mysql|mssql|tcp|pivot|tunnel|intranet)\b`),
		tools: []hintedTool{
			{"raw_tcp", "走任务隧道做原生协议探测"},
			{"impacket_proxy", "impacket 类工具经任务 SOCKS5"},
		},
	},
	{
		zh: []string{"复现", "验证漏洞", "确认漏洞"},
		en: regexp.MustCompile(`(?i)\b(reproduce|repro|verify|confirm|poc)\b`),
		tools: []hintedTool{
			{"report_finding_gated", "HTTP/服务类确认漏洞:带 proof_kind + observation_ids"},
		},
	},
}

// maxHintTools caps how many tool names a single hint block may advertise.
const maxHintTools = 5

// ToolRoutingHint returns a short, intent-specific tool recommendation block, or
// "" when nothing matches. built must be the agent's final (already resolved)
// tool list: tools that are unbound or disabled are never recommended.
func ToolRoutingHint(intentPayload json.RawMessage, built []actool.CoreTool) string {
	if len(intentPayload) == 0 || len(built) == 0 {
		return ""
	}
	available := make(map[string]bool, len(built))
	for _, t := range built {
		available[t.Name()] = true
	}
	text := strings.ToLower(string(intentPayload))
	seen := map[string]bool{}
	var lines []hintedTool
	for _, r := range toolHintRules {
		if !toolHintRuleMatches(r, text) {
			continue
		}
		for _, cand := range r.tools {
			if !available[cand.name] || seen[cand.name] {
				continue
			}
			seen[cand.name] = true
			lines = append(lines, cand)
			if len(lines) >= maxHintTools {
				break
			}
		}
		if len(lines) >= maxHintTools {
			break
		}
	}
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n**本意图推荐工具(代码按意图关键词匹配,优先使用;同类命令会被 Bash 闸门拦下)**:\n")
	for _, l := range lines {
		b.WriteString("- `")
		b.WriteString(l.name)
		b.WriteString("`:")
		b.WriteString(l.why)
		b.WriteByte('\n')
	}
	return b.String()
}

func toolHintRuleMatches(r toolHintRule, lowerText string) bool {
	for _, k := range r.zh {
		if strings.Contains(lowerText, k) {
			return true
		}
	}
	if r.en != nil && r.en.MatchString(lowerText) {
		return true
	}
	return false
}

// ToolRoutingHeader is the code-owned, always-present top block of the worker
// system prompt. It states the routing map in one breath, before any role text,
// because a rule that only appears at the tail of a multi-thousand-token prompt
// measured at zero calls in production.
const ToolRoutingHeader = `【工具优先 · 代码闸门】侦察/扫描/审计先找专用工具:HTTP 单请求 recon_http、基线差分 http_diff、端口 scan_rustscan、路径 path_probe、鉴权 auth_probe、指纹 fingerprint、管理面 admin_surface、前端/JS 源码 web_audit、SQLi sqlmap_run、模板 nuclei_run、原生 TCP raw_tcp、确认漏洞 report_finding_gated。Bash 里手搓 curl/wget/Invoke-WebRequest、nmap/rustscan/masscan、sqlmap、nuclei 会被闸门拒绝并提示对应工具;确需原生命令(上传/流式/大文件/私有脚本)时传 override_reason。

`
