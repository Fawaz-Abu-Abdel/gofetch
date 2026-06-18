package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// SSLResult contains the TLS certificate details extracted from port 443.
type SSLResult struct {
	Subject         string    // Common Name of the leaf certificate
	Issuer          string    // Common Name of the issuing CA
	IssuedAt        time.Time // NotBefore
	ExpiresAt       time.Time // NotAfter
	DaysUntilExpiry int       // negative when already expired
	IsExpired       bool
	SANs            []string // Subject Alternative Names (DNS)
	Error           string   // non-empty when the connection or handshake failed
}

// GetSSL opens a TLS connection to domain:443, extracts the leaf certificate,
// and returns structured metadata. The connection is closed immediately after
// the handshake; no HTTP traffic is exchanged.
func GetSSL(domain string) *SSLResult {
	result := &SSLResult{}

	// Strip any scheme so we always connect to the bare hostname.
	host := StripScheme(domain)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	cfg := &tls.Config{
		ServerName: host,
		// InsecureSkipVerify is intentionally false: we want real cert data.
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), cfg)
	if err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Error = "server returned no certificates"
		return result
	}

	leaf := certs[0]
	now := time.Now()

	result.Subject = leaf.Subject.CommonName
	result.Issuer = leaf.Issuer.CommonName
	result.IssuedAt = leaf.NotBefore
	result.ExpiresAt = leaf.NotAfter
	result.IsExpired = now.After(leaf.NotAfter)
	result.DaysUntilExpiry = int(leaf.NotAfter.Sub(now).Hours() / 24)
	result.SANs = leaf.DNSNames

	return result
}
