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

// IsGitWorkTree reports whether dir is inside a Git working tree.
func IsGitWorkTree(dir string) (bool, error) {
	root, err := FindGitRoot(dir)
	if err != nil {
		return false, err
	}
	return root != "", nil
}
