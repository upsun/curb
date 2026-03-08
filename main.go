package main

import (
	"fmt"
	"os"

	"github.com/platformsh/curb/cmd"
)

func main() {
	// If _CURB_INIT is set, this process is the re-exec'd child init.
	// Stub: child init will be implemented in WP03.
	if os.Getenv("_CURB_INIT") != "" {
		fmt.Fprintln(os.Stderr, "curb: child init not yet implemented")
		os.Exit(111)
	}

	if err := cmd.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "curb:", err)
		os.Exit(1)
	}
}
