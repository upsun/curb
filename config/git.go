package config

import (
	"os"
	"path/filepath"
	"strings"
)

// IsGitWorkTree reports whether dir is inside a Git working tree.
// It walks from dir upward to the filesystem root, checking for a .git directory or .git file (worktree).
func IsGitWorkTree(dir string) (bool, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	for {
		gitPath := filepath.Join(dir, ".git")
		info, err := os.Stat(gitPath)
		if err == nil {
			if info.IsDir() {
				return true, nil
			}
			// .git file: check it starts with "gitdir:" (Git worktree format).
			data, err := os.ReadFile(gitPath)
			if err != nil {
				return false, err
			}
			if strings.HasPrefix(string(data), "gitdir:") {
				return true, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false, nil
}
