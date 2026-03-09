package config

import (
	"os"
	"path/filepath"
	"strings"
)

// FindGitRoot returns the root directory of the Git working tree containing dir.
// It walks from dir upward to the filesystem root, checking for a .git directory or .git file (worktree).
// If dir is not inside a Git working tree, it returns ("", nil).
func FindGitRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		gitPath := filepath.Join(dir, ".git")
		info, err := os.Stat(gitPath)
		if err == nil {
			if info.IsDir() {
				return dir, nil
			}
			// .git file: check it starts with "gitdir:" (Git worktree format).
			data, err := os.ReadFile(gitPath)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(string(data), "gitdir:") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", nil
}

// FindGitHooksDir returns the hooks directory for a Git working tree rooted at gitRoot.
// For regular repos, this is <gitRoot>/.git/hooks.
// For worktrees (where .git is a file), it resolves the real git dir and returns <gitdir>/hooks.
// Returns "" if no hooks directory exists.
func FindGitHooksDir(gitRoot string) string {
	gitPath := filepath.Join(gitRoot, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return ""
	}
	var gitDir string
	if info.IsDir() {
		gitDir = gitPath
	} else {
		// .git file: extract the gitdir path.
		data, err := os.ReadFile(gitPath)
		if err != nil {
			return ""
		}
		line := strings.TrimSpace(string(data))
		if !strings.HasPrefix(line, "gitdir:") {
			return ""
		}
		ref := strings.TrimSpace(line[len("gitdir:"):])
		if !filepath.IsAbs(ref) {
			ref = filepath.Join(gitRoot, ref)
		}
		gitDir = ref
	}
	hooksDir := filepath.Join(gitDir, "hooks")
	if s, err := os.Stat(hooksDir); err == nil && s.IsDir() {
		return hooksDir
	}
	return ""
}

// IsGitWorkTree reports whether dir is inside a Git working tree.
func IsGitWorkTree(dir string) (bool, error) {
	root, err := FindGitRoot(dir)
	if err != nil {
		return false, err
	}
	return root != "", nil
}
