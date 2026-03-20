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
	"syscall"
	"testing"

	"github.com/upsun/curb/sandbox"
)

var (
	curbBin   string
	srtBin    string
	srtScript string // resolved path to srt's JS entry point (for bun)
	bunBin    string
	curlBin   string
	testCaps  *sandbox.Capabilities
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
	if srtBin != "" {
		// Resolve symlink to get the JS entry point for running under bun.
		if resolved, err := filepath.EvalSymlinks(srtBin); err == nil {
			srtScript = resolved
		}
	}
	bunBin, _ = exec.LookPath("bun")
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

func requireProxyNS(b *testing.B) {
	b.Helper()
	requireUserNS(b)
	if testCaps.NetNS != nil {
		b.Skipf("network namespaces unavailable: %v", testCaps.NetNS)
	}
}

func requireNetNS(b *testing.B) {
	b.Helper()
	requireProxyNS(b)
	if testCaps.TUN() != nil {
		b.Skipf("TUN/TAP unavailable: %v", testCaps.TUN())
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

// srtBunAvailable caches whether srt can run under bun.
var srtBunAvailable *bool

func requireSRTBun(b *testing.B) {
	b.Helper()
	if bunBin == "" {
		b.Skip("bun not installed")
	}
	if srtScript == "" {
		b.Skip("srt not installed or symlink unresolvable")
	}
	if srtBunAvailable == nil {
		cmd := exec.Command(bunBin, srtScript, "-c", "true")
		ok := cmd.Run() == nil
		srtBunAvailable = &ok
	}
	if !*srtBunAvailable {
		b.Skip("srt cannot run under bun")
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
		var rss rssTracker
		for b.Loop() {
			cmd := exec.Command(curbBin, "--", trueBin)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
			rss.observe(cmd)
		}
		rss.report(b)
	})

	benchSRT(b, srtConfig{
		Network:    srtNetwork{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
	}, "true")
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

// peakRSSKB returns the peak resident set size in KB from a finished command.
// On Linux, wait4() reports RUSAGE_BOTH (self + reaped children), so this
// captures the sandbox orchestrator and everything it spawned.
func peakRSSKB(cmd *exec.Cmd) int64 {
	if cmd.ProcessState == nil {
		return 0
	}
	rusage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0
	}
	return rusage.Maxrss
}

// rssTracker tracks peak RSS across benchmark iterations and reports it.
type rssTracker struct {
	max int64
}

func (t *rssTracker) observe(cmd *exec.Cmd) {
	if rss := peakRSSKB(cmd); rss > t.max {
		t.max = rss
	}
}

func (t *rssTracker) report(b *testing.B) {
	if t.max > 0 {
		b.ReportMetric(float64(t.max), "KB:peak-RSS")
	}
}

// srtRunner describes how to invoke srt under a particular JS runtime.
type srtRunner struct {
	name    string
	require func(*testing.B)
	cmd     func(cfg, shellCmd string) *exec.Cmd
}

var srtRunners = []srtRunner{
	{
		name:    "srt-node",
		require: requireSRT,
		cmd: func(cfg, shellCmd string) *exec.Cmd {
			return exec.Command(srtBin, "--settings", cfg, "-c", shellCmd)
		},
	},
	{
		name:    "srt-bun",
		require: requireSRTBun,
		cmd: func(cfg, shellCmd string) *exec.Cmd {
			return exec.Command(bunBin, srtScript, "--settings", cfg, "-c", shellCmd)
		},
	},
}

// benchSRT runs a sub-benchmark for each srt runner.
func benchSRT(b *testing.B, srtCfg srtConfig, shellCmd string) {
	for _, r := range srtRunners {
		b.Run(r.name, func(b *testing.B) {
			r.require(b)
			cfg := writeSRTConfig(b, srtCfg)
			var rss rssTracker
			for b.Loop() {
				cmd := r.cmd(cfg, shellCmd)
				if out, err := cmd.CombinedOutput(); err != nil {
					b.Fatalf("%s: %v\n%s", r.name, err, out)
				}
				rss.observe(cmd)
			}
			rss.report(b)
		})
	}
}

// BenchmarkHTTPSingle measures boot + one HTTP request per sandbox invocation.
func BenchmarkHTTPSingle(b *testing.B) {
	requireCurl(b)
	port := httpBenchServer(b)

	b.Run("curb-proxy", func(b *testing.B) {
		requireProxyNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		var rss rssTracker
		for b.Loop() {
			cmd := exec.Command(curbBin,
				"--domains", "localhost",
				"--allow-http",
				"--write", "*",
				"--exec", "*",
				"--", curlBin, "-so", "/dev/null", url,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
			rss.observe(cmd)
		}
		rss.report(b)
	})

	b.Run("curb-tun", func(b *testing.B) {
		requireNetNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		var rss rssTracker
		for b.Loop() {
			cmd := exec.Command(curbBin,
				"--proxy", "off",
				"--domains", "localhost",
				"--allow-http",
				"--write", "*",
				"--exec", "*",
				"--", curlBin, "-so", "/dev/null", url,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
			rss.observe(cmd)
		}
		rss.report(b)
	})

	// Unset no_proxy so curl uses srt's HTTP proxy instead of
	// trying to connect directly (which fails inside bwrap's
	// unshared network namespace).
	hip := hostIP()
	srtCurlCmd := fmt.Sprintf(`NO_PROXY="" no_proxy="" curl -so /dev/null http://%s:%d/`, hip, port)
	benchSRT(b, srtConfig{
		Network:    srtNetwork{AllowedDomains: []string{hip}, DeniedDomains: []string{}},
		Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
	}, srtCurlCmd)
}

const httpBatchSize = 10

// BenchmarkHTTPBatch measures per-request network overhead by running
// multiple curl requests inside a single sandbox invocation.
// Divide ns/op by httpBatchSize (10) to get per-request latency.
func BenchmarkHTTPBatch(b *testing.B) {
	requireCurl(b)
	port := httpBenchServer(b)

	b.Run("curb-proxy", func(b *testing.B) {
		requireProxyNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		shCmd := curlLoop(httpBatchSize, fmt.Sprintf("-so /dev/null %s", url))
		var rss rssTracker
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
			rss.observe(cmd)
		}
		rss.report(b)
	})

	b.Run("curb-tun", func(b *testing.B) {
		requireNetNS(b)
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		shCmd := curlLoop(httpBatchSize, fmt.Sprintf("-so /dev/null %s", url))
		var rss rssTracker
		for b.Loop() {
			cmd := exec.Command(curbBin,
				"--proxy", "off",
				"--domains", "localhost",
				"--allow-http",
				"--write", "*",
				"--exec", "*",
				"--", "sh", "-c", shCmd,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				b.Fatalf("curb: %v\n%s", err, out)
			}
			rss.observe(cmd)
		}
		rss.report(b)
	})

	// Unset no_proxy so curl uses srt's HTTP proxy.
	hip := hostIP()
	srtURL := fmt.Sprintf("http://%s:%d/", hip, port)
	srtShCmd := curlLoop(httpBatchSize, fmt.Sprintf(`-so /dev/null %s`, srtURL))
	srtCmd := fmt.Sprintf(`NO_PROXY="" no_proxy="" sh -c '%s'`, srtShCmd)
	benchSRT(b, srtConfig{
		Network:    srtNetwork{AllowedDomains: []string{hip}, DeniedDomains: []string{}},
		Filesystem: srtFilesystem{AllowWrite: []string{"/tmp"}, DenyRead: []string{}, DenyWrite: []string{}},
	}, srtCmd)
}
