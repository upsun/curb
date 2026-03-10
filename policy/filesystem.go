//go:build linux

package policy

import (
	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Access right sets without execute permission.
const (
	accessReadOnly  = ll.AccessFSReadFile | ll.AccessFSReadDir
	accessReadWrite = accessReadOnly |
		ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile |
		ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg |
		ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock |
		ll.AccessFSMakeSym | ll.AccessFSTruncate
)

// BuildLandlockRules constructs Landlock rules from read-only, read-write, and exec path lists.
// When execPaths is non-empty, RO and RW paths get no EXECUTE permission;
// only execPaths receive EXECUTE. When execPaths is empty (--allow-exec '*'),
// the standard RODirs/RWDirs rules are used which include EXECUTE.
func BuildLandlockRules(roPaths, rwPaths, execPaths []string) []landlock.Rule {
	var rules []landlock.Rule
	if len(execPaths) > 0 {
		if len(roPaths) > 0 {
			rules = append(rules, landlock.PathAccess(accessReadOnly, roPaths...).IgnoreIfMissing())
		}
		if len(rwPaths) > 0 {
			rules = append(rules, landlock.PathAccess(accessReadWrite, rwPaths...).IgnoreIfMissing())
		}
		rules = append(rules, landlock.PathAccess(ll.AccessFSExecute, execPaths...).IgnoreIfMissing())
	} else {
		if len(roPaths) > 0 {
			rules = append(rules, landlock.RODirs(roPaths...).IgnoreIfMissing())
		}
		if len(rwPaths) > 0 {
			rules = append(rules, landlock.RWDirs(rwPaths...).IgnoreIfMissing())
		}
	}
	return rules
}

// EnforceLandlock applies the given Landlock rules using the best available ABI version.
func EnforceLandlock(rules []landlock.Rule) error {
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
