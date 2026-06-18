package scanner

import (
	"context"
	"net"
	"strings"
	"time"
)

// MXRecord holds a single mail-exchanger entry.
type MXRecord struct {
	Host     string
	Priority uint16
}

// DNSResult contains all resolved DNS records for a domain.
// Per-record-type errors are collected in Errors; a failed lookup
// does not abort the others.
type DNSResult struct {
	ARecords    []string   // IPv4 addresses
	AAAARecords []string   // IPv6 addresses
	CNAMERecord string     // empty when the domain has no CNAME alias
	MXRecords   []MXRecord // sorted by priority (ascending) by the resolver
	TXTRecords  []string
	Errors      []string // non-fatal, per-record-type error messages
}

// GetDNS performs a full DNS interrogation for the given domain.
// All lookups share a single 10 s deadline context.
func GetDNS(domain string) *DNSResult {
	result := &DNSResult{}

	// Normalise: strip scheme so 'https://example.com' resolves correctly.
	domain = StripScheme(domain)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := net.DefaultResolver

	// ── A / AAAA ──────────────────────────────────────────────────────────
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, "A/AAAA: "+unwrapDNSErr(err))
	} else {
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				result.ARecords = append(result.ARecords, addr.IP.String())
			} else {
				result.AAAARecords = append(result.AAAARecords, addr.IP.String())
			}
		}
	}

	// ── CNAME ─────────────────────────────────────────────────────────────
	// LookupCNAME always returns the canonical name (with trailing dot).
	// When there is no CNAME record the canonical name equals the queried
	// domain itself — we treat that as "no CNAME".
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, "CNAME: "+unwrapDNSErr(err))
	} else {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, domain) {
			result.CNAMERecord = cname
		}
	}

	// ── MX ────────────────────────────────────────────────────────────────
	mxs, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, "MX: "+unwrapDNSErr(err))
	} else {
		for _, mx := range mxs {
			result.MXRecords = append(result.MXRecords, MXRecord{
				Host:     strings.TrimSuffix(mx.Host, "."),
				Priority: mx.Pref,
			})
		}
	}

	// ── TXT ───────────────────────────────────────────────────────────────
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, "TXT: "+unwrapDNSErr(err))
	} else {
		result.TXTRecords = txts
	}

	return result
}

// unwrapDNSErr extracts a concise message from a *net.DNSError.
func unwrapDNSErr(err error) string {
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsNotFound {
			return "record not found"
		}
		if dnsErr.IsTimeout {
			return "lookup timed out"
		}
		return dnsErr.Err
	}
	return err.Error()
}
