package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// --- 纯函数：端点评分 ---

func TestEvaluateAssetDispatchHighValueEndpoint(t *testing.T) {
	port, status := 8443, 200
	a := &db.Asset{
		ID:         11,
		Type:       "endpoint",
		URL:        "https://app.example.com:8443/api/v1/user?id=42",
		Port:       &port,
		StatusCode: &status,
		Method:     "POST",
		Params: []map[string]any{
			{"location": "query", "name": "id", "value": "42"},
			{"location": "body", "name": "name", "value": "x"},
		},
	}
	d := EvaluateAssetDispatch(a)
	if d.Skip != "" {
		t.Fatalf("高价值端点不应被跳过: %+v", d)
	}
	if d.Score < 8 {
		t.Fatalf("score=%d, want >=8 (%+v)", d.Score, d)
	}
	if d.Priority < 9 {
		t.Fatalf("priority=%d, want >=9 (%+v)", d.Priority, d)
	}
	for _, want := range []string{"endpoint", "API", "ID 参数", "非常规端口"} {
		if !containsReason(d.Reasons, want) {
			t.Errorf("reasons=%v 缺少 %q", d.Reasons, want)
		}
	}
}

func TestEvaluateAssetDispatchHardSkips(t *testing.T) {
	status404, status412, status200 := 404, 412, 200
	cases := []struct {
		name     string
		asset    *db.Asset
		wantKind string
	}{
		{
			name:     "静态 JS",
			asset:    &db.Asset{ID: 1, Type: "service", URL: "https://x.example.com/static/app.js"},
			wantKind: "static",
		},
		{
			name:     "静态字体",
			asset:    &db.Asset{ID: 2, Type: "service", URL: "https://x.example.com/fonts/a.woff2"},
			wantKind: "static",
		},
		{
			name:     "CDN 边缘主机",
			asset:    &db.Asset{ID: 3, Type: "subdomain", Domain: "cdn.jsdelivr.net"},
			wantKind: "cdn",
		},
		{
			name:     "CDN 前缀主机",
			asset:    &db.Asset{ID: 4, Type: "service", URL: "https://cdn-edge.example.com/app"},
			wantKind: "cdn",
		},
		{
			name:     "CNAME 到 CDN",
			asset:    &db.Asset{ID: 5, Type: "subdomain", Domain: "img.example.com", RecordType: "CNAME", RecordValue: []string{"d123.cloudfront.net"}},
			wantKind: "cdn",
		},
		{
			name:     "历史 404",
			asset:    &db.Asset{ID: 6, Type: "service", URL: "https://x.example.com/admin", StatusCode: &status404},
			wantKind: "http_404_412",
		},
		{
			name:     "历史 412",
			asset:    &db.Asset{ID: 7, Type: "service", URL: "https://x.example.com/api", StatusCode: &status412},
			wantKind: "http_404_412",
		},
		{
			name:     "正常资产不跳过",
			asset:    &db.Asset{ID: 8, Type: "service", URL: "https://x.example.com/login", StatusCode: &status200},
			wantKind: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := EvaluateAssetDispatch(tc.asset)
			if d.SkipKind != tc.wantKind {
				t.Fatalf("SkipKind=%q want %q (%+v)", d.SkipKind, tc.wantKind, d)
			}
			if tc.wantKind != "" && d.Skip == "" {
				t.Fatalf("硬跳过必须给出可读原因: %+v", d)
			}
		})
	}
}

func TestEvaluateAssetDispatchURLIDParam(t *testing.T) {
	status := 200
	a := &db.Asset{ID: 13, Type: "service", URL: "https://x.example.com/api/order?id=9", StatusCode: &status}
	d := EvaluateAssetDispatch(a)
	if d.Skip != "" {
		t.Fatalf("unexpected skip: %+v", d)
	}
	if !containsReason(d.Reasons, "URL 带 ID 参数") {
		t.Fatalf("reasons=%v, want URL 带 ID 参数", d.Reasons)
	}
}

func TestEvaluateAssetDispatchUnauthPanel(t *testing.T) {
	status := 200
	a := &db.Asset{ID: 9, Type: "service", URL: "https://x.example.com/admin", StatusCode: &status, PageTitle: "后台管理"}
	d := EvaluateAssetDispatch(a)
	if d.Skip != "" {
		t.Fatalf("unexpected skip: %+v", d)
	}
	if !containsReason(d.Reasons, "未鉴权面板") {
		t.Fatalf("reasons=%v, want 未鉴权面板", d.Reasons)
	}
	if d.Score < 4 {
		t.Fatalf("score=%d, want >=4", d.Score)
	}
}

func TestDispatchPriorityForScoreMonotonic(t *testing.T) {
	prev := 0
	for score := 0; score <= dispatchMaxScore; score++ {
		p := DispatchPriorityForScore(score)
		if p < prev {
			t.Fatalf("priority 应随评分单调不降: score=%d p=%d prev=%d", score, p, prev)
		}
		if p < 1 || p > 10 {
			t.Fatalf("priority=%d 越界", p)
		}
		prev = p
	}
	if got := DispatchPriorityForScore(dispatchMaxScore); got != 10 {
		t.Fatalf("满分 priority=%d, want 10", got)
	}
}

// --- 纯函数：探测类识别 / 404-412 提取 ---

func TestProbeKindForText(t *testing.T) {
	cases := map[string]string{
		"对 example.com 登录口做 sql 注入测试": ProbeInjection,
		"爆破后台登录口令":                    ProbeAuth,
		"枚举 /admin 目录与备份文件":           ProbeExposure,
		"识别指纹与技术栈":                    ProbeFingerprint,
		"扫描子域与路径":                     ProbeDiscovery,
		"测试 API 接口参数":                 ProbeAPI,
		"提权并横向移动":                     ProbeExploit,
		"看看这个站":                       ProbeGeneric,
		"Exploit Author 专用意图":         ProbeExploit,
		"author 字段":                   ProbeGeneric, // 不能把 author 误判成 auth
	}
	for text, want := range cases {
		if got := probeKindForText(text); got != want {
			t.Errorf("probeKindForText(%q)=%q want %q", text, got, want)
		}
	}
}

func TestHTTPMissStatuses(t *testing.T) {
	cases := []struct {
		text string
		want []int
	}{
		{"curl -s -o /dev/null -w '%{http_code}' https://x/admin -> 404", []int{404}},
		{"探测 /admin 返回 404", []int{404}},
		{"HTTP/1.1 412 Precondition Failed", []int{412}},
		{"响应长度 4120 字节", nil},
		{"id=412&page=1", nil},
		{"GET /api/user 200 OK", nil},
		{"目标端口关闭，无响应", nil},
		{"404 Not Found", []int{404}},
	}
	for _, tc := range cases {
		got := httpMissStatuses(tc.text)
		if len(got) != len(tc.want) {
			t.Errorf("httpMissStatuses(%q)=%v want %v", tc.text, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("httpMissStatuses(%q)=%v want %v", tc.text, got, tc.want)
				break
			}
		}
	}
}

// --- 否定索引 ---

func TestNegationIndexRepeated404Blocks(t *testing.T) {
	idx := newNegationIndex()
	svc := &db.Asset{ID: 7, Type: "service"}
	idx.addHit(7, ProbeDiscovery, 404, 100, false)
	if _, ok := idx.blocked(svc, ProbeDiscovery); ok {
		t.Fatal("单次 404 不应拉黑")
	}
	idx.addHit(7, ProbeDiscovery, 404, 101, false)
	h, ok := idx.blocked(svc, ProbeDiscovery)
	if !ok || h == nil || h.Hits != NegationRepeats {
		t.Fatalf("连续两次 404 应拉黑: ok=%v hit=%+v", ok, h)
	}
	// 不同探测类不受影响（service 资产按探测类隔离）。
	if _, ok := idx.blocked(svc, ProbeInjection); ok {
		t.Fatal("不同探测类不应被一起拉黑")
	}
}

func TestNegationIndexEndpointBlocksAnyProbe(t *testing.T) {
	idx := newNegationIndex()
	ep := &db.Asset{ID: 8, Type: "endpoint"}
	idx.addHit(8, ProbeDiscovery, 404, 1, false)
	idx.addHit(8, ProbeDiscovery, 404, 2, false)
	if _, ok := idx.blocked(ep, ProbeInjection); !ok {
		t.Fatal("endpoint 已确认不存在时应挡住任何探测类")
	}
}

// 404 事实常被归到 discovery，而 planner 写的意图可能带 api；两者应视为同一族。
func TestNegationIndexAPIDiscoveryFamily(t *testing.T) {
	idx := newNegationIndex()
	svc := &db.Asset{ID: 12, Type: "service"}
	idx.addHit(12, ProbeDiscovery, 404, 1, false)
	idx.addHit(12, ProbeDiscovery, 404, 2, false)
	if _, ok := idx.blocked(svc, ProbeAPI); !ok {
		t.Fatal("discovery 的否定应能挡住同族的 api 探测")
	}
	if _, ok := idx.blocked(svc, ProbeInjection); ok {
		t.Fatal("不同族（注入）不应被 discovery 的否定挡住")
	}
}

func TestNegationIndexClearBreaksStreak(t *testing.T) {
	idx := newNegationIndex()
	idx.addHit(9, ProbeDiscovery, 404, 1, false)
	idx.clear(9, ProbeDiscovery)
	idx.addHit(9, ProbeDiscovery, 404, 2, false)
	if _, ok := idx.blocked(&db.Asset{ID: 9, Type: "service"}, ProbeDiscovery); ok {
		t.Fatal("中间出现非 404 结果后，不应按连续两次拉黑")
	}
}

func TestNegationIndexExplicitNegatedIsSticky(t *testing.T) {
	idx := newNegationIndex()
	idx.addHit(10, ProbeAuth, 0, 1, true)
	idx.clear(10, ProbeAuth)
	if _, ok := idx.blocked(&db.Asset{ID: 10, Type: "service"}, ProbeAuth); !ok {
		t.Fatal("显式 negated 事实应立即拉黑且不被后续 clear 撤销")
	}
}

func TestBuildNegationIndexFromFacts(t *testing.T) {
	fact := func(id int64, payload map[string]any) *db.Node {
		raw, _ := json.Marshal(payload)
		return &db.Node{ID: id, Kind: db.KindFact, State: "confirmed", Payload: raw}
	}
	// facts 按 id 降序（最新在前）；两条 404 命中同一资产 + 同一探测类。
	facts := []*db.Node{
		fact(101, map[string]any{"summary": "探测 /admin 返回 404", "evidence": "GET /admin -> 404"}),
		fact(100, map[string]any{"summary": "探测 /admin 返回 404", "evidence": "GET /admin -> 404"}),
	}
	idx := buildNegationIndexFrom(facts, map[int64][]int64{100: {5}, 101: {5}})
	h, ok := idx.blocked(&db.Asset{ID: 5, Type: "service"}, ProbeDiscovery)
	if !ok || h == nil || h.Hits != 2 {
		t.Fatalf("应聚合成连续 2 次 404: ok=%v hit=%+v", ok, h)
	}

	// 中间夹一条同探测类的非 404 结果 → 连续计数被打断。
	facts = []*db.Node{
		fact(102, map[string]any{"summary": "目录扫描完成，/login 可访问"}),
		fact(101, map[string]any{"summary": "探测 /admin 返回 404", "evidence": "GET /admin -> 404"}),
	}
	idx = buildNegationIndexFrom(facts, map[int64][]int64{101: {5}, 102: {5}})
	if _, ok := idx.blocked(&db.Asset{ID: 5, Type: "service"}, ProbeDiscovery); ok {
		t.Fatal("非 404 结果应打断连续计数")
	}
}

func TestAnnotateAssetsSortsSkipLast(t *testing.T) {
	status := 200
	tools := NewToolSet(nil, "planner")
	assets := []*db.Asset{
		{ID: 1, Type: "service", URL: "https://x.example.com/static/a.js", StatusCode: &status},
		{ID: 2, Type: "endpoint", URL: "https://x.example.com/api/user?id=1", StatusCode: &status, Method: "GET", Params: []map[string]any{{"name": "id"}}},
	}
	views := tools.annotateAssets(assets, newNegationIndex())
	if len(views) != 2 {
		t.Fatalf("views=%d", len(views))
	}
	if views[0].ID != 2 || views[1].ID != 1 {
		t.Fatalf("应按评分降序且 skip 沉底: %d,%d", views[0].ID, views[1].ID)
	}
	if views[1].DispatchSkip == "" {
		t.Fatal("静态资源应带 dispatch_skip")
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if strings.Contains(r, want) {
			return true
		}
	}
	return false
}
