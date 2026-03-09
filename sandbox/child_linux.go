//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ChildInit is the entry point for the re-exec'd child process inside new namespaces.
// It reads the sandbox config from fd 3, applies sandbox layers (stubs for now),
// and execs the target command. It never returns on success.
func ChildInit() {
	if err := childInit(); err != nil {
		fmt.Fprintf(os.Stderr, "curb: child init: %v\n", err)
		os.Exit(111)
	}
}

func childInit() error {
	configFile := os.NewFile(3, "config-pipe")
	sockFile := os.NewFile(4, "socketpair")

	var cfg ChildConfig
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	configFile.Close()

	// TODO(WP07): Use sockFile for TAP fd passing.
	sockFile.Close()

	// TODO(WP04-WP06): Apply sandbox layers (filesystem, exec, network).

	if len(cfg.Command) == 0 {
		return fmt.Errorf("no command specified")
	}

	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		return err
	}

	return syscall.Exec(exe, cfg.Command, cfg.Env)
}

// findExecutable resolves a command name to an absolute path using the PATH from env.
func findExecutable(name string, env []string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	var pathEnv string
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathEnv = e[5:]
			break
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", name)
}
