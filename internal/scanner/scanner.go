// Package scanner is the core reconnaissance engine for the gofetch CLI tool.
// It exposes five independent probe functions and a Run orchestrator that
// executes them in two phases:
//
//	Phase 1 (sequential): GetDNS — needed to obtain an IP for phases below.
//	Phase 2 (concurrent): GetSSL, GetHeaders, GetGeoIP, ScanPorts.
package scanner

import (
	"fmt"
	"strings"
	"sync"
)

// Version is the scanner package version, exported for CLI display.
const Version = "0.1.0"

// ScanResult aggregates all probe results for a single target.
type ScanResult struct {
	Target  string
	Verbose bool
	DNS     *DNSResult
	SSL     *SSLResult
	Headers *HeadersResult
	GeoIP   *GeoIPResult
	Ports   *PortsResult
}

// Run normalises the target then executes all probes across two phases,
// returning the fully populated ScanResult.
//
// Phase 1 — DNS (sequential): required to extract an IP address for GeoIP
// and port scanning; typically completes in < 500 ms.
//
// Phase 2 — concurrent: SSL, HTTP headers, GeoIP, and port scan run in
// parallel goroutines, each writing to result under mu.
func Run(target string, verbose bool) (*ScanResult, error) {
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	domain := StripScheme(target)
	result := &ScanResult{Target: domain, Verbose: verbose}

	// ── Phase 1: DNS ──────────────────────────────────────────────────────────
	result.DNS = GetDNS(domain)
	ip := firstIP(result.DNS)

	// ── Phase 2: concurrent probes ────────────────────────────────────────────
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	wg.Add(4)

	go func() {
		defer wg.Done()
		r := GetSSL(domain)
		mu.Lock(); result.SSL = r; mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := GetHeaders(domain)
		mu.Lock(); result.Headers = r; mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := GetGeoIP(ip)
		mu.Lock(); result.GeoIP = r; mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := ScanPorts(ip, nil) // nil → uses CommonPorts
		mu.Lock(); result.Ports = r; mu.Unlock()
	}()

	wg.Wait()
	return result, nil
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// StripScheme removes a leading http:// or https:// from a raw input string
// so that probe functions always receive a bare hostname or IP.
// Exported so cmd/ can normalise the target once before fanning out.
func StripScheme(raw string) string {
	raw = strings.TrimSpace(raw)
	if after, ok := strings.CutPrefix(raw, "https://"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(raw, "http://"); ok {
		return after
	}
	return raw
}

// firstIP extracts the first IPv4 address from DNS results.
// Returns an empty string when no A records are available so callers
// that require an IP can check and surface a friendly error.
func firstIP(dns *DNSResult) string {
	if dns != nil && len(dns.ARecords) > 0 {
		return dns.ARecords[0]
	}
	return ""
}
