package msf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeClass(t *testing.T) {
	cases := map[string]string{
		"Apache Struts2 S2-045":      "struts2",
		"log4shell (CVE-2021-44228)": "log4j",
		"WebLogic 未授权 RCE":           "weblogic",
		"MS17-010 EternalBlue":       "eternalblue",
		"redis 未授权访问":                "redis",
		"Tomcat CVE-2017-12615":      "tomcat",
		"unknown-thing":              "",
	}
	for in, want := range cases {
		if got := NormalizeClass(in); got != want {
			t.Fatalf("NormalizeClass(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBuildWebClassLeavesPayloadToModule(t *testing.T) {
	p, err := Build(Input{VulnClass: "Tomcat CVE-2017-12615", Host: "127.0.0.1", Port: 8080,
		URL: "http://127.0.0.1:8080", LHOST: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Candidates {
		if c.Module == "exploit/multi/http/tomcat_jsp_upload_bypass" {
			found = true
			if c.Payload != "" {
				t.Fatalf("Web 载体模块不应写死 PAYLOAD（MSF 需按 target 自选），得到 %q", c.Payload)
			}
		}
	}
	if !found {
		t.Fatal("缺少 tomcat_jsp_upload_bypass 候选")
	}
}

func TestBuildNativePayloadByOS(t *testing.T) {
	win, err := Build(Input{VulnClass: "redis 未授权", Host: "10.0.0.9", OS: "windows", LHOST: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(win.Candidates) == 0 {
		t.Fatal("no candidates")
	}
	if got := win.Candidates[0].Payload; !strings.HasPrefix(got, "windows/") {
		t.Fatalf("os=windows 应选 windows payload，得到 %q", got)
	}
	lin, err := Build(Input{VulnClass: "redis 未授权", Host: "10.0.0.9", OS: "linux", LHOST: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lin.Candidates[0].Payload; !strings.HasPrefix(got, "linux/") {
		t.Fatalf("os=linux 应选 linux payload，得到 %q", got)
	}
}

func TestBuildCredentialOptionsAndPlanID(t *testing.T) {
	base := Input{VulnClass: "tomcat", Host: "127.0.0.1", Port: 8080, URL: "http://127.0.0.1:8080"}
	without, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	withCreds := base
	withCreds.Username = "tomcat"
	withCreds.Password = "s3cret"
	with, err := Build(withCreds)
	if err != nil {
		t.Fatal(err)
	}
	if len(with.Candidates) == 0 {
		t.Fatal("no candidates")
	}
	c := with.Candidates[0]
	if c.Options["HttpUsername"] != "tomcat" || c.Options["HttpPassword"] != "s3cret" {
		t.Fatalf("凭据未写入模块选项：%v", c.Options)
	}
	if without.Candidates[0].Options["HttpUsername"] != "" {
		t.Fatal("无凭据时不应写 HttpUsername")
	}
	if with.PlanID == without.PlanID {
		t.Fatal("plan_id 应随凭据变化（同输入同结果，不同输入不同结果）")
	}
}

func TestBuildDeterministicAndOptions(t *testing.T) {
	ssl := true
	in := Input{
		VulnClass: "Struts2 S2-045",
		Host:      "10.0.0.5",
		Port:      8443,
		URL:       "https://10.0.0.5:8443/app/login.action",
		LHOST:     "10.0.0.1",
		LPORT:     4444,
		SSL:       &ssl,
	}
	p1, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := Build(in)
	if p1.PlanID != p2.PlanID {
		t.Fatalf("plan id not deterministic: %s vs %s", p1.PlanID, p2.PlanID)
	}
	if p1.Class != "struts2" || len(p1.Candidates) == 0 {
		t.Fatalf("bad plan: %+v", p1)
	}
	c := p1.Candidates[0]
	if c.Options["RHOSTS"] != "10.0.0.5" || c.Options["RPORT"] != "8443" || c.Options["SSL"] != "true" {
		t.Fatalf("bad options: %+v", c.Options)
	}
	if c.Options["TARGETURI"] != "/app/login.action" {
		t.Fatalf("targeturi: %q", c.Options["TARGETURI"])
	}
	// struts2 属于 Web 载体类模块：PAYLOAD 由模块按 target 自选，不应写死。
	if c.Payload != "" {
		t.Fatalf("struts2 不应写死 payload: %q", c.Payload)
	}
	if len(p1.Preconditions) == 0 || !strings.Contains(p1.Preconditions[0], "port_open") {
		t.Fatalf("no preconditions: %+v", p1.Preconditions)
	}
}

func TestBuildUnknownClass(t *testing.T) {
	_, err := Build(Input{VulnClass: "some-new-cve", Host: "1.2.3.4"})
	if err == nil {
		t.Fatal("want ErrNoPlan")
	}
	var np *ErrNoPlan
	if !asErr(err, &np) || !strings.Contains(np.Search, "some-new-cve") {
		t.Fatalf("bad error: %#v", err)
	}
}

func asErr(err error, target **ErrNoPlan) bool {
	e, ok := err.(*ErrNoPlan)
	if ok {
		*target = e
	}
	return ok
}

func TestNextBranches(t *testing.T) {
	p, err := Build(Input{VulnClass: "struts2", Host: "10.0.0.5", Port: 80, LHOST: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	// first failure → retry candidate 1
	a := Next(p, 0, OutcomeNoSession)
	if a.Kind != "retry" || a.CandidateIndex != 1 || a.Candidate == nil {
		t.Fatalf("want retry #1, got %+v", a)
	}
	// last failure → stop
	a = Next(p, len(p.Candidates)-1, OutcomeError)
	if a.Kind != "stop" {
		t.Fatalf("want stop, got %+v", a)
	}
	// session
	a = Next(p, 0, OutcomeSession)
	if a.Kind != "session" || len(a.PostSteps) == 0 {
		t.Fatalf("want session + post steps, got %+v", a)
	}
	// precondition failure → degrade
	a = Next(p, 0, OutcomePrecheckFailed)
	if a.Kind != "degrade" {
		t.Fatalf("want degrade, got %+v", a)
	}
	// module missing → retry
	a = Next(p, 0, OutcomeModuleMissing)
	if a.Kind != "retry" {
		t.Fatalf("want retry, got %+v", a)
	}
}

func TestWindowsPayloadForSMB(t *testing.T) {
	p, err := Build(Input{VulnClass: "eternalblue", Host: "10.0.0.9", LHOST: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Candidates[0].Options["PAYLOAD"], "windows/x64") {
		t.Fatalf("payload=%q", p.Candidates[0].Options["PAYLOAD"])
	}
	if p.Candidates[0].Options["RPORT"] != "445" {
		t.Fatalf("rport=%q", p.Candidates[0].Options["RPORT"])
	}
}

func TestPlanJSONShape(t *testing.T) {
	p, _ := Build(Input{VulnClass: "weblogic", Host: "h", Port: 7001, LHOST: "1.1.1.1"})
	if _, err := json.Marshal(p); err != nil {
		t.Fatal(err)
	}
}
