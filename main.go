package main

import (
	"fmt"
	"os"

	"github.com/upsun/curb/cmd"
	"github.com/upsun/curb/sandbox"
)

func main() {
	// If _CURB_INIT is set, this process is the re-exec'd child inside new namespaces.
	if os.Getenv(sandbox.InitEnvKey) != "" {
		sandbox.ChildInit()
		os.Exit(sandbox.ExitSetupFailure) // Unreachable: ChildInit execs the target or exits on error.
	}

	if err := cmd.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "curb:", err)
		os.Exit(1)
	}
}
