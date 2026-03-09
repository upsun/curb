package main

import (
	"fmt"
	"os"

	"github.com/platformsh/curb/cmd"
	"github.com/platformsh/curb/sandbox"
)

func main() {
	// If _CURB_INIT is set, this process is the re-exec'd child inside new namespaces.
	if os.Getenv("_CURB_INIT") != "" {
		sandbox.ChildInit()
		os.Exit(111) // Unreachable: ChildInit execs the target or exits on error.
	}

	if err := cmd.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "curb:", err)
		os.Exit(1)
	}
}
