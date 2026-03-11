//go:build linux

package bench

import (
	"encoding/json"
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
	srtBin   string
	curlBin  string
	testCaps *sandbox.Capabilities
)

func TestMain(m *testing.M) {
	// Re-exec guard for curb child process.
	if os.Getenv(sandbox.InitEnvKey) != "" {
		sandbox.ChildInit()
		os.Exit(sandbox.ExitSetupFailure)
	}
	if os.Getenv(sandbox.TUNProbeEnvKey) != "" {
		sandbox.RunTUNProbe()
		return
	}

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

	srtBin, _ = exec.LookPath("srt")
	curlBin, _ = exec.LookPath("curl")

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func requireUserNS(b *testing.B) {
	b.Helper()
	if testCaps.UserNS != nil {
		b.Skipf("user namespaces unavailable: %v", testCaps.UserNS)
	}
}

func requireNetNS(b *testing.B) {
	b.Helper()
	requireUserNS(b)
	if testCaps.NetNS != nil {
		b.Skipf("network namespaces unavailable: %v", testCaps.NetNS)
	}
	if testCaps.TUN != nil {
		b.Skipf("TUN/TAP unavailable: %v", testCaps.TUN)
	}
}

// srtAvailable caches whether srt can actually run (bwrap may fail under AppArmor).
var srtAvailable *bool

func requireSRT(b *testing.B) {
	b.Helper()
	if srtBin == "" {
		b.Skip("srt not installed")
	}
	if srtAvailable == nil {
		// Probe: try running a trivial command under srt.
		cmd := exec.Command(srtBin, "-c", "true")
		ok := cmd.Run() == nil
		srtAvailable = &ok
	}
	if !*srtAvailable {
		b.Skip("srt cannot run (bwrap namespace setup failed)")
	}
}

func requireCurl(b *testing.B) {
	b.Helper()
	if curlBin == "" {
		b.Skip("curl not installed")
	}
}

// srt JSON config structs.
type srtConfig struct {
	Network    srtNetwork    `json:"network"`
	Filesystem srtFilesystem `json:"filesystem"`
}

type srtNetwork struct {
	AllowedDomains []string `json:"allowedDomains"`
	DeniedDomains  []string `json:"deniedDomains"`
}

type srtFilesystem struct {
	AllowWrite []string `json:"allowWrite"`
	DenyRead   []string `json:"denyRead"`
	DenyWrite  []string `json:"denyWrite"`
}

// writeSRTConfig writes an srt settings JSON file and returns its path.
func writeSRTConfig(b *testing.B, cfg srtConfig) string {
	b.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatalf("marshal srt config: %v", err)
	}
	p := filepath.Join(b.TempDir(), "srt-settings.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		b.Fatalf("write srt config: %v", err)
	}
	return p
}

// hostIP returns the routable host IP via UDP dial trick.
func hostIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close() //nolint:errcheck
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// BenchmarkBoot measures sandbox setup/teardown overhead by running `true`.
func BenchmarkBoot(b *testing.B) {
	trueBin, err := exec.LookPath("true")
	if err != nil {
		b.Fatalf("true not found: %v", err)
	}

	b.Run("curb", func(b *testing.B) {
		requireUserNS(b)
		for b.Loop() {
			cmd := exec.Command(curbBin, "--", trueBin)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
		}
	})

	b.Run("srt", func(b *testing.B) {
		requireSRT(b)
		cfg := writeSRTConfig(b, srtConfig{
			Network:    srtNetwork{AllowedDomains: []string{}, DeniedDomains: []string{}},
			Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
		})
		for b.Loop() {
			cmd := exec.Command(srtBin, "--settings", cfg, "-c", "true")
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("srt: %v\n%s", err, out)
			}
		}
	})
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
	ln, err := net.Listen("tcp", "0.0.0.0:0")
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
	requireCurl(b)
	port := httpBenchServer(b)

	b.Run("curb", func(b *testing.B) {
		requireNetNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		for b.Loop() {
			cmd := exec.Command(curbBin,
				"--domains", "localhost",
				"--write", "*",
				"--exec", "*",
				"--", curlBin, "-so", "/dev/null", url,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
		}
	})

	b.Run("srt", func(b *testing.B) {
		requireSRT(b)
		hip := hostIP()
		url := fmt.Sprintf("http://%s:%d/", hip, port)
		cfg := writeSRTConfig(b, srtConfig{
			Network:    srtNetwork{AllowedDomains: []string{hip}, DeniedDomains: []string{}},
			Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
		})
		// Unset no_proxy so curl uses srt's HTTP proxy instead of
		// trying to connect directly (which fails inside bwrap's
		// unshared network namespace).
		curlCmd := fmt.Sprintf(`NO_PROXY="" no_proxy="" curl -so /dev/null %s`, url)
		for b.Loop() {
			cmd := exec.Command(srtBin, "--settings", cfg, "-c", curlCmd)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("srt: %v\n%s", err, out)
			}
		}
	})
}

const httpBatchSize = 10

// BenchmarkHTTPBatch measures per-request network overhead by running
// multiple curl requests inside a single sandbox invocation.
// Divide ns/op by httpBatchSize (10) to get per-request latency.
func BenchmarkHTTPBatch(b *testing.B) {
	requireCurl(b)
	port := httpBenchServer(b)

	b.Run("curb", func(b *testing.B) {
		requireNetNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		shCmd := curlLoop(httpBatchSize, fmt.Sprintf("-so /dev/null %s", url))
		for b.Loop() {
			cmd := exec.Command(curbBin,
				"--domains", "localhost",
				"--write", "*",
				"--exec", "*",
				"--", "sh", "-c", shCmd,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
		}
	})

	b.Run("srt", func(b *testing.B) {
		requireSRT(b)
		hip := hostIP()
		url := fmt.Sprintf("http://%s:%d/", hip, port)
		cfg := writeSRTConfig(b, srtConfig{
			Network:    srtNetwork{AllowedDomains: []string{hip}, DeniedDomains: []string{}},
			Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
		})
		shCmd := curlLoop(httpBatchSize, fmt.Sprintf(`-so /dev/null %s`, url))
		// Unset no_proxy so curl uses srt's HTTP proxy.
		srtCmd := fmt.Sprintf(`export NO_PROXY="" no_proxy=""; %s`, shCmd)
		for b.Loop() {
			cmd := exec.Command(srtBin, "--settings", cfg, "-c", srtCmd)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("srt: %v\n%s", err, out)
			}
		}
	})
}
