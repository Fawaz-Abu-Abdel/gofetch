package cmd

import (
	"sync"

	"github.com/fawaz/gofetch/internal/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan subcommand.
var scanCmd = &cobra.Command{
	Use:   "scan <domain|url>",
	Short: "Run reconnaissance against a target domain or URL",
	Long: `scan performs modular reconnaissance against a target.

Examples:
  gofetch scan example.com
  gofetch scan https://example.com
  gofetch scan 192.168.1.1`,
	Args: cobra.ExactArgs(1),
	Run:  runScan,
}

// runScan orchestrates the two-phase reconnaissance workflow.
//
// Phase 1 (sequential) — DNS:
//
//	GetDNS must complete first so its A records can be forwarded to the
//	IP-dependent probes in Phase 2.
//
// Phase 2 (concurrent, 4 goroutines) — SSL · Headers · GeoIP · Ports:
//
//	All four probes run in parallel. Each goroutine holds mu only for the
//	instant it writes its result pointer into the shared ScanResult; I/O
//	itself is entirely outside the critical section.
//	A sync.WaitGroup gates the spinner and the call to PrintResults.
func runScan(cmd *cobra.Command, args []string) {
	target := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")
	domain := scanner.StripScheme(target)

	pterm.Println()
	pterm.Info.Printfln("Target : %s", pterm.LightCyan(domain))
	if verbose {
		pterm.Debug.Println("Verbose mode — probe errors shown inline")
	}
	pterm.Println()

	// ── Shared state ──────────────────────────────────────────────────────────
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		result = &scanner.ScanResult{Target: domain, Verbose: verbose}
	)

	// ─────────────────────────────────────────────────────────────────────────
	// PHASE 1 — DNS (sequential, ~100–500 ms)
	// Required before Phase 2: GeoIP and ScanPorts need a routable IP.
	// ─────────────────────────────────────────────────────────────────────────
	spinner, _ := pterm.DefaultSpinner.
		WithText("Resolving DNS records...").
		WithRemoveWhenDone(false).
		Start()

	result.DNS = scanner.GetDNS(domain)
	ip := extractIP(result.DNS)

	if verbose && ip == "" {
		pterm.Warning.Println("No A record found — GeoIP and port scan will be skipped")
	}

	// ─────────────────────────────────────────────────────────────────────────
	// PHASE 2 — Concurrent probes (SSL · Headers · GeoIP · Ports)
	// Each goroutine acquires mu only for the pointer assignment, not for I/O.
	// ─────────────────────────────────────────────────────────────────────────
	spinner.UpdateText("Interrogating target...")

	// Goroutine 1: TLS certificate
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := scanner.GetSSL(domain)
		mu.Lock()
		result.SSL = r
		mu.Unlock()
	}()

	// Goroutine 2: HTTP response headers
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := scanner.GetHeaders(domain)
		mu.Lock()
		result.Headers = r
		mu.Unlock()
	}()

	// Goroutine 3: GeoIP — uses IP resolved in Phase 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := scanner.GetGeoIP(ip)
		mu.Lock()
		result.GeoIP = r
		mu.Unlock()
	}()

	// Goroutine 4: TCP port scan — uses IP resolved in Phase 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := scanner.ScanPorts(ip, nil) // nil → scanner.CommonPorts
		mu.Lock()
		result.Ports = r
		mu.Unlock()
	}()

	// Block until every goroutine has written its result.
	wg.Wait()
	spinner.Success("Done")
	pterm.Println()

	// Delegate all formatting to formatter.go — scan.go owns no display logic.
	PrintResults(result)
}

// extractIP returns the first IPv4 A record from a DNS result, or "".
// An empty return means GeoIP and ScanPorts will receive an empty IP and
// surface their own "no IP provided" errors gracefully.
func extractIP(dns *scanner.DNSResult) string {
	if dns != nil && len(dns.ARecords) > 0 {
		return dns.ARecords[0]
	}
	return ""
}

func init() {
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().StringP("output", "o", "", "Write results to file (e.g. --output results.json)")
	scanCmd.Flags().StringP("format", "f", "text", "Output format: text | json | csv")
	scanCmd.Flags().IntP("timeout", "t", 30, "HTTP timeout in seconds")
}
