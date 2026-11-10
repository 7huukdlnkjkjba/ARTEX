package agent

// Task-scope enforcement for host-side tools that execute a binary rather than a
// shell command. The Bash guard already checks the hosts it can extract from a
// command line; a tool that carries its target in a structured field (DC host,
// RustScan target) must run the same check itself.
//
// Semantics match guard.HostInTaskScope: known=false means the task has no
// registered scope, so the caller stays fail-open (the platform's existing
// behavior). known=true + inScope=false is a hard denial.

import (
	"fmt"
	"net"
	"strings"

	"github.com/Autumn-27/artex/guard"
)

// assertInScope rejects a target outside the task's registered scope. target may
// be an IP, a hostname/FQDN, or a CIDR. A hostname is resolved and every resolved
// address must be in scope: scanning a name that partly points outside the RoE is
// still an out-of-scope action.
func (t *ToolSet) assertInScope(target string) error {
	if t.scopeOff { // 主 Agent:范围层硬阻断已撤销,目标由操作员把关
		return nil
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		if !t.cidrInScope(ipnet) {
			return scopeDenied(target)
		}
		return nil
	}
	if inScope, known := guard.HostInTaskScope(t.taskID, target); !known || inScope {
		return nil
	}
	// A CIDR-only scope contains the target's IP but not its FQDN. Resolve and
	// require every address to be authorized before denying a hostname target.
	if net.ParseIP(target) == nil {
		if ips, err := net.LookupHost(target); err == nil && len(ips) > 0 {
			allIn := true
			knownScope := false
			for _, ip := range ips {
				in, known := guard.HostInTaskScope(t.taskID, ip)
				if known {
					knownScope = true
				}
				if known && !in {
					allIn = false
				}
			}
			if allIn && knownScope {
				return nil
			}
		}
	}
	return scopeDenied(target)
}

// cidrInScope accepts a CIDR only when both ends of its range are inside the
// task scope. This rejects a /16 target under a /24 scope while allowing a /25
// target under a /24 scope. It is an approximation (a non-contiguous set of
// scope rows could still hide a gap), deliberately biased toward denial.
func (t *ToolSet) cidrInScope(n *net.IPNet) bool {
	if n == nil {
		return false
	}
	first, last := cidrEndpoints(n)
	for _, ip := range []net.IP{first, last} {
		in, known := guard.HostInTaskScope(t.taskID, ip.String())
		if !known {
			return true // no registered scope: fail-open
		}
		if !in {
			return false
		}
	}
	return true
}

// cidrEndpoints returns the first and last address of a network.
func cidrEndpoints(n *net.IPNet) (net.IP, net.IP) {
	first := n.IP.Mask(n.Mask)
	last := make(net.IP, len(first))
	for i := range first {
		last[i] = first[i] | ^n.Mask[i]
	}
	return first, last
}

// cidrHostCount returns the number of addresses in a CIDR (0 if the mask is
// invalid). Used to reject accidentally huge scans (/8) before they start.
func cidrHostCount(n *net.IPNet) uint64 {
	if n == nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	if bits <= 0 || ones < 0 {
		return 0
	}
	hostBits := bits - ones
	if hostBits >= 64 {
		return ^uint64(0)
	}
	return uint64(1) << hostBits
}

func scopeDenied(target string) error {
	return fmt.Errorf("目标 %s 不在本任务已登记的 scope 内，拒绝执行（先在任务里用 add_task_scope 登记授权范围）", target)
}
