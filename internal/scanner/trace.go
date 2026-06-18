package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// TraceMetrics holds network trace durations for a single request.
type TraceMetrics struct {
	DNSLookup       time.Duration
	TCPConnection   time.Duration
	TLSHandshake    time.Duration
	ServerProcess   time.Duration // Time to First Byte (TTFB)
	ContentTransfer time.Duration
	TotalTime       time.Duration
}

// MetricStats stores aggregated statistical metrics.
type MetricStats struct {
	Min time.Duration
	Max time.Duration
	Avg time.Duration
}

// TraceSummary aggregates statistics across multiple iterations.
type TraceSummary struct {
	DNSLookup       MetricStats
	TCPConnection   MetricStats
	TLSHandshake    MetricStats
	ServerProcess   MetricStats
	ContentTransfer MetricStats
	TotalTime       MetricStats
	Count           int
}

// TraceURL runs precision HTTP network traces over the specified number of iterations.
func TraceURL(target string, count int) (*TraceSummary, error) {
	if count <= 0 {
		return nil, fmt.Errorf("iteration count must be at least 1")
	}

	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	var runs []TraceMetrics

	for i := 0; i < count; i++ {
		metrics, err := runTraceIteration(parsedURL)
		if err != nil {
			return nil, fmt.Errorf("iteration %d failed: %v", i+1, err)
		}
		runs = append(runs, *metrics)
	}

	return aggregateSummary(runs), nil
}

func runTraceIteration(u *url.URL) (*TraceMetrics, error) {
	var (
		dnsStart, dnsDone             time.Time
		connStart, connDone           time.Time
		tlsStart, tlsDone             time.Time
		firstByte, bodyDone           time.Time
		connectDoneCalled, tlsCalled  bool
	)

	req, err := http.NewRequestWithContext(context.Background(), "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Disable connection reuse to force full TCP and TLS handshakes in every run
	req.Close = true

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if connStart.IsZero() {
				connStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connectDoneCalled {
				connDone = time.Now()
				connectDoneCalled = true
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
			tlsCalled = true
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsDone = time.Now()
			}
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Force disable keepalives on transport level
	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	bodyDone = time.Now()

	metrics := &TraceMetrics{
		TotalTime: bodyDone.Sub(t0),
	}

	// Calculate specific stages based on captured trace hooks
	if !dnsDone.IsZero() && !dnsStart.IsZero() {
		metrics.DNSLookup = dnsDone.Sub(dnsStart)
	}

	if !connDone.IsZero() && !connStart.IsZero() {
		metrics.TCPConnection = connDone.Sub(connStart)
	}

	if tlsCalled && !tlsDone.IsZero() && !tlsStart.IsZero() {
		metrics.TLSHandshake = tlsDone.Sub(tlsStart)
	}

	// Server Processing Time (TTFB) starts from connect/TLS done to first byte
	endConnect := connDone
	if tlsCalled && !tlsDone.IsZero() {
		endConnect = tlsDone
	}

	if !firstByte.IsZero() && !endConnect.IsZero() {
		metrics.ServerProcess = firstByte.Sub(endConnect)
	}

	if !bodyDone.IsZero() && !firstByte.IsZero() {
		metrics.ContentTransfer = bodyDone.Sub(firstByte)
	}

	return metrics, nil
}

func aggregateSummary(runs []TraceMetrics) *TraceSummary {
	summary := &TraceSummary{
		Count: len(runs),
	}

	dns := extractList(runs, func(m TraceMetrics) time.Duration { return m.DNSLookup })
	summary.DNSLookup = computeStats(dns)

	tcp := extractList(runs, func(m TraceMetrics) time.Duration { return m.TCPConnection })
	summary.TCPConnection = computeStats(tcp)

	tls := extractList(runs, func(m TraceMetrics) time.Duration { return m.TLSHandshake })
	summary.TLSHandshake = computeStats(tls)

	ttfb := extractList(runs, func(m TraceMetrics) time.Duration { return m.ServerProcess })
	summary.ServerProcess = computeStats(ttfb)

	transfer := extractList(runs, func(m TraceMetrics) time.Duration { return m.ContentTransfer })
	summary.ContentTransfer = computeStats(transfer)

	tot := extractList(runs, func(m TraceMetrics) time.Duration { return m.TotalTime })
	summary.TotalTime = computeStats(tot)

	return summary
}

func extractList(runs []TraceMetrics, fn func(TraceMetrics) time.Duration) []time.Duration {
	var list []time.Duration
	for _, r := range runs {
		v := fn(r)
		if v > 0 {
			list = append(list, v)
		}
	}
	return list
}

func computeStats(vals []time.Duration) MetricStats {
	if len(vals) == 0 {
		return MetricStats{}
	}
	min := vals[0]
	max := vals[0]
	var sum time.Duration

	for _, v := range vals {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		sum += v
	}

	return MetricStats{
		Min: min,
		Max: max,
		Avg: sum / time.Duration(len(vals)),
	}
}
