package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	// SkillDirEnvKey is the env var pointing to the agent skill directory
	// containing SKILL.md with sandbox constraints.
	SkillDirEnvKey = "CURB_SKILL_DIR"

	// skillPrimaryDir is the primary skill directory (agentskills.io convention).
	skillPrimaryDir = ".agents/skills/curb"

	// skillSymlinkDir is a symlink target for Claude Code discovery.
	skillSymlinkDir = ".claude/skills/curb"
)

// formatSkill generates an agent-skills-compliant SKILL.md describing
// the active sandbox constraints.
func formatSkill(plan *SandboxPlan) string {
	var b strings.Builder
	b.WriteString(`---
name: curb
description: Active sandbox constraints for this environment. Check when encountering permission errors, file not found, or network connection failures.
---

# Sandbox Constraints
`)

	// Filesystem.
	if !plan.NoFSRestrict || !plan.NoExecRestrict {
		b.WriteString("\n## Filesystem\n")
		writeSkillList(&b, "Read-only paths", plan.ROPaths)
		writeSkillList(&b, "Read-only files", plan.ROFiles)
		writeSkillList(&b, "Read-write paths", plan.RWPaths)
		writeSkillList(&b, "Read-write files", plan.RWFiles)
		writeSkillList(&b, "Executable", plan.ExecPaths)
		writeSkillList(&b, "Hidden", plan.HiddenPaths)
		writeSkillList(&b, "Deny write", plan.DenyWritePaths)
		writeSkillList(&b, "Deny exec", plan.DenyExecPaths)
	}

	// Network.
	b.WriteString("\n## Network\n")
	if plan.UnrestrictedNet {
		b.WriteString("- Mode: unrestricted\n")
	} else {
		if len(plan.AllowedDomains) > 0 {
			fmt.Fprintf(&b, "- Allowed domains: %s\n", strings.Join(plan.AllowedDomains, ", "))
		}
		if len(plan.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "- Allowed IPs: %s\n", strings.Join(plan.AllowedIPs, ", "))
		}
		if plan.ProxyEnabled {
			fmt.Fprintf(&b, "- Proxy: 127.0.0.1:%d\n", plan.ProxyPort)
			if plan.SOCKSPort > 0 {
				fmt.Fprintf(&b, "- SOCKS5: 127.0.0.1:%d\n", plan.SOCKSPort)
			}
		}
		if plan.HostLoopback {
			b.WriteString("- Localhost: forwarded to host\n")
		} else if plan.ProxyEnabled {
			b.WriteString("- Localhost: sandbox-internal\n")
		}
		if len(plan.InjectBindings) > 0 {
			dests := make([]string, 0, len(plan.InjectBindings))
			for t := range plan.InjectBindings {
				dests = append(dests, displayInjectTarget(t))
			}
			sort.Strings(dests)
			fmt.Fprintf(&b, "- Credential injection: requests to %s have their credential substituted in transit. The relevant environment variable holds a placeholder, so use it normally; the real value is never present in this sandbox, so do not expect or look for one.\n", strings.Join(dests, ", "))
		}
		if !plan.ProxyEnabled && len(plan.AllowedDomains) == 0 && len(plan.AllowedIPs) == 0 {
			b.WriteString("- Allowed: none\n")
		}
	}

	// Environment.
	b.WriteString("\n## Environment\n")
	keys := make([]string, 0, len(plan.EnvSet))
	for k := range plan.EnvSet {
		if k == SkillDirEnvKey {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var setParts []string
	for _, k := range keys {
		setParts = append(setParts, k+"="+plan.EnvSet[k])
	}
	if len(setParts) > 0 {
		b.WriteString("- Set:\n")
		for _, p := range setParts {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}
	if len(plan.EnvPassthrough) > 0 {
		b.WriteString("- Passthrough:\n")
		for _, p := range plan.EnvPassthrough {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}

	return b.String()
}

// symlinkSkillDir creates a best-effort symlink at baseDir/.claude/skills/curb
// pointing (relatively) to targetDir. Errors are silently ignored — the env
// var is the authoritative pointer; the symlink is for agent auto-discovery.
func symlinkSkillDir(baseDir, targetDir string) {
	parent := filepath.Join(baseDir, filepath.Dir(skillSymlinkDir))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return
	}
	rel, err := filepath.Rel(parent, targetDir)
	if err != nil {
		rel = targetDir
	}
	_ = os.Symlink(rel, filepath.Join(baseDir, skillSymlinkDir))
}

// writeSkillList writes a Markdown sub-list under a label, one item per line.
func writeSkillList(b *strings.Builder, label string, items []string) {
	if len(items) > 0 {
		fmt.Fprintf(b, "- %s:\n", label)
		for _, item := range items {
			fmt.Fprintf(b, "  - %s\n", item)
		}
	}
}

// writeSkill writes the sandbox constraints as an agent skill (SKILL.md) to
// ~/.agents/skills/curb/ and symlinks ~/.claude/skills/curb/ to it. When HOME
// differs from TempDir, a bind-mount entry is added so the skill directory
// appears under the real HOME inside the mount namespace.
func writeSkill(plan *SandboxPlan, tmpDir string) error {
	content := formatSkill(plan)

	home := plan.EnvSet["HOME"]
	if home == "" {
		home = plan.SandboxHome
	}
	if home == "" {
		home = tmpDir
	}

	// Write SKILL.md to the primary location.
	primaryDir := filepath.Join(tmpDir, skillPrimaryDir)
	if err := os.MkdirAll(primaryDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(primaryDir, "SKILL.md"), []byte(content), 0o644); err != nil {
		return err
	}

	// Symlink .claude/skills/curb -> .agents/skills/curb (relative).
	symlinkSkillDir(tmpDir, primaryDir)

	// When HOME is not the TempDir, agents won't scan TempDir for skills.
	// On Linux with mount NS, bind-mount the skill directory under the
	// real HOME so agents discover it. On macOS (no mount namespaces)
	// or Linux without mount NS, auto-discovery only works when HOME is
	// TempDir; the env var is the fallback.
	//
	// The mount point must be created on the real filesystem before the
	// sandbox starts (inside the mount NS, HOME may be read-only). If
	// HOME is read-only on the host too (e.g. --read /home/user without
	// --write), MkdirAll fails and the env var is the fallback.
	// Point the env var at the HOME-relative path only when a bind mount
	// will make it available there (requires mount NS); otherwise use
	// the TempDir path.
	envDir := primaryDir
	if home != tmpDir && runtime.GOOS == "linux" && plan.UsePivotRoot {
		dst := filepath.Join(home, skillPrimaryDir)
		if err := os.MkdirAll(dst, 0o755); err == nil {
			plan.SkillMounts = append(plan.SkillMounts, [2]string{primaryDir, dst})
			envDir = dst
			// Ensure the skill directory is in the read allowlist so
			// Landlock (defense-in-depth) permits access.
			plan.ROPaths = appendUniq(plan.ROPaths, dst)

			// Symlink HOME/.claude/skills/curb -> the bind-mounted
			// primary dir so agents discover it via ~/.claude/skills/.
			symlinkSkillDir(home, dst)
		}
	}

	plan.EnvSet[SkillDirEnvKey] = envDir
	return nil
}
