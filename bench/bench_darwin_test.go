//go:build darwin

package bench

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/upsun/curb/sandbox"
)

var (
	curbBin  string
	testCaps *sandbox.Capabilities
)

func TestMain(m *testing.M) {
	testCaps = sandbox.ProbeAll()

	// Build curb binary.
	dir, err := os.MkdirTemp("", "curb-bench-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}

	curbBin = filepath.Join(dir, "curb")
	cmd := exec.Command("go", "build", "-o", curbBin)
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s\n", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func requireSeatbelt(b *testing.B) {
	b.Helper()
	if testCaps.Seatbelt != nil {
		b.Skipf("seatbelt unavailable: %v", testCaps.Seatbelt)
	}
}

func requireCurl(b *testing.B) {
	b.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		b.Skip("curl not installed")
	}
}

// BenchmarkBoot measures sandbox setup/teardown overhead by running `true`.
func BenchmarkBoot(b *testing.B) {
	requireSeatbelt(b)

	trueBin, err := exec.LookPath("true")
	if err != nil {
		b.Fatalf("true not found: %v", err)
	}

	for b.Loop() {
		cmd := exec.Command(curbBin, "--", trueBin)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.Fatalf("curb: %v\n%s", err, out)
		}
	}
}

// httpBenchServer starts a local HTTP server and returns the port.
// The server is shut down when the benchmark finishes.
func httpBenchServer(b *testing.B) int {
	b.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	b.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// curlLoop returns a shell command that runs curl N times in a loop.
func curlLoop(n int, curlArgs string) string {
	return fmt.Sprintf(`for i in $(seq %d); do curl %s; done`, n, curlArgs)
}

// BenchmarkHTTPSingle measures boot + one HTTP request per sandbox invocation.
func BenchmarkHTTPSingle(b *testing.B) {
	requireSeatbelt(b)
	requireCurl(b)

	port := httpBenchServer(b)
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	shCmd := fmt.Sprintf("curl -so /dev/null %s", url)

	for b.Loop() {
		cmd := exec.Command(curbBin,
			"--domains", "localhost",
			"--allow-http",
			"--write", "*",
			"--exec", "*",
			"--", "sh", "-c", shCmd,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.Fatalf("curb: %v\n%s", err, out)
		}
	}
}

const httpBatchSize = 10

// BenchmarkHTTPBatch measures per-request network overhead by running
// multiple curl requests inside a single sandbox invocation.
// Divide ns/op by httpBatchSize (10) to get per-request latency.
func BenchmarkHTTPBatch(b *testing.B) {
	requireSeatbelt(b)
	requireCurl(b)

	port := httpBenchServer(b)
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	shCmd := curlLoop(httpBatchSize, fmt.Sprintf("-so /dev/null %s", url))

	for b.Loop() {
		cmd := exec.Command(curbBin,
			"--domains", "localhost",
			"--allow-http",
			"--write", "*",
			"--exec", "*",
			"--", "sh", "-c", shCmd,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			b.Fatalf("curb: %v\n%s", err, out)
		}
	}
}
