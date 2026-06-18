package scanner

import (
	"fmt"
	"net/http"
	"time"
)

// SecurityHeaders groups the presence/absence of common HTTP security headers.
// An empty string means the header was not present in the response.
type SecurityHeaders struct {
	StrictTransportSecurity string // HSTS
	XFrameOptions           string
	XContentTypeOptions     string
	ContentSecurityPolicy   string
	XXSSProtection          string
	ReferrerPolicy          string
	PermissionsPolicy       string
}

// HeadersResult contains the HTTP response metadata for a domain.
type HeadersResult struct {
	FinalURL   string          // after following redirects
	StatusCode int
	Server     string
	XPoweredBy string
	Security   SecurityHeaders
	Error      string // non-empty on transport or connection failure
}

// GetHeaders issues an HTTPS GET to the domain (falling back to HTTP if HTTPS
// fails), follows up to 5 redirects, and extracts response headers.
// The response body is discarded — only headers are read.
func GetHeaders(domain string) *HeadersResult {
	result := &HeadersResult{}

	host := StripScheme(domain)
	target := "https://" + host

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		// HTTPS failed — attempt plain HTTP as a fallback.
		target = "http://" + host
		resp, err = client.Get(target)
		if err != nil {
			result.Error = fmt.Sprintf("HTTP request failed: %v", err)
			return result
		}
	}
	defer resp.Body.Close()

	h := resp.Header

	result.FinalURL = resp.Request.URL.String()
	result.StatusCode = resp.StatusCode
	result.Server = h.Get("Server")
	result.XPoweredBy = h.Get("X-Powered-By")
	result.Security = SecurityHeaders{
		StrictTransportSecurity: h.Get("Strict-Transport-Security"),
		XFrameOptions:           h.Get("X-Frame-Options"),
		XContentTypeOptions:     h.Get("X-Content-Type-Options"),
		ContentSecurityPolicy:   h.Get("Content-Security-Policy"),
		XXSSProtection:          h.Get("X-XSS-Protection"),
		ReferrerPolicy:          h.Get("Referrer-Policy"),
		PermissionsPolicy:       h.Get("Permissions-Policy"),
	}

	return result
}
