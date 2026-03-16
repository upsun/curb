//go:build linux

package policy

import (
	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Access right sets without execute permission.
const (
	accessReadOnly  = ll.AccessFSReadFile | ll.AccessFSReadDir
	accessRWFile    = ll.AccessFSReadFile | ll.AccessFSWriteFile | ll.AccessFSTruncate
	accessReadWrite = accessReadOnly |
		ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile |
		ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg |
		ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock |
		ll.AccessFSMakeSym | ll.AccessFSTruncate
)

// BuildLandlockRules constructs Landlock rules from the given path sets.
// When Exec is non-empty, RO and RW paths get no EXECUTE permission;
// only Exec paths receive EXECUTE. When Exec is empty (--allow-exec '*'),
// the standard RODirs/RWDirs rules are used which include EXECUTE.
func BuildLandlockRules(p LandlockPaths) []landlock.Rule {
	var rules []landlock.Rule
	if len(p.Exec) > 0 {
		if len(p.RODirs) > 0 {
			rules = append(rules, landlock.PathAccess(accessReadOnly, p.RODirs...).IgnoreIfMissing())
		}
		if len(p.ROFiles) > 0 {
			rules = append(rules, landlock.PathAccess(ll.AccessFSReadFile, p.ROFiles...).IgnoreIfMissing())
		}
		if len(p.RWDirs) > 0 {
			rules = append(rules, landlock.PathAccess(accessReadWrite, p.RWDirs...).IgnoreIfMissing())
		}
		if len(p.RWFiles) > 0 {
			rules = append(rules, landlock.PathAccess(accessRWFile, p.RWFiles...).IgnoreIfMissing())
		}
		rules = append(rules, landlock.PathAccess(ll.AccessFSExecute, p.Exec...).IgnoreIfMissing())
	} else {
		if len(p.RODirs) > 0 {
			rules = append(rules, landlock.RODirs(p.RODirs...).IgnoreIfMissing())
		}
		if len(p.ROFiles) > 0 {
			rules = append(rules, landlock.ROFiles(p.ROFiles...).IgnoreIfMissing())
		}
		if len(p.RWDirs) > 0 {
			rules = append(rules, landlock.RWDirs(p.RWDirs...).IgnoreIfMissing())
		}
		if len(p.RWFiles) > 0 {
			rules = append(rules, landlock.RWFiles(p.RWFiles...).IgnoreIfMissing())
		}
	}
	return rules
}

// EnforceLandlock applies the given Landlock rules using the best available ABI version.
func EnforceLandlock(rules []landlock.Rule) error {
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
