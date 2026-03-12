package main

import (
	"os"

	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/cmd"
	"github.com/upsun/curb/sandbox"
)

func main() {
	// If _CURB_INIT is set, this process is the re-exec'd child inside new namespaces.
	if os.Getenv(sandbox.InitEnvKey) != "" {
		sandbox.ChildInit()
		os.Exit(sandbox.ExitSetupFailure) // Unreachable: ChildInit execs the target or exits on error.
	}

	// Mount probe child: test mount operations inside a user+mount namespace.
	if os.Getenv(sandbox.MountProbeEnvKey) != "" {
		sandbox.RunMountProbe()
		return
	}

	// TUN probe child: test TUNSETIFF inside a user+net namespace.
	if os.Getenv(sandbox.TUNProbeEnvKey) != "" {
		sandbox.RunTUNProbe()
		return
	}

	if err := cmd.NewRootCmd().Execute(); err != nil {
		clog.Errorf("%v", err)
		os.Exit(1)
	}
}
