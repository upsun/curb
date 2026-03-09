//go:build !linux

package sandbox

import (
	"fmt"
	"os"
)

// ChildInit is not supported on non-Linux platforms.
func ChildInit() {
	fmt.Fprintln(os.Stderr, "curb: child init not supported on this platform")
	os.Exit(111)
}
