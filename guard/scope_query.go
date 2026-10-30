package guard

import "strings"

// HostInTaskScope reports whether host belongs to a task's registered scope.
// known=false means the task has no scope rows (or the scope layer is disabled),
// in which case the caller must keep the existing fail-open behaviour. It is the
// same scope set the Bash/shell_open enforcement path uses, exposed for host-side
// tools that execute a script instead of a command string (e.g. exploit_run,
// whose target lives inside the file and is therefore invisible to host
// extraction).
func HostInTaskScope(taskID int64, host string) (inScope bool, known bool) {
	if taskID <= 0 || strings.TrimSpace(host) == "" {
		return true, false
	}
	if !scopeEnforceOn() {
		return true, false
	}
	set := loadScope(taskID)
	if set == nil || set.rows == 0 {
		return true, false
	}
	return set.hostInScope(host), true
}
