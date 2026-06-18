// Package cmd — formatter.go
// Owns all output rendering for the scan subcommand.
// Every scanner result section is formatted as a pterm table, then wrapped
// in a named box for a clean, professional UNIX tool aesthetic.
package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/fawaz/gofetch/internal/scanner"
	"github.com/pterm/pterm"
)

// ─────────────────────────────────────────────────────────────────────────────
// Public entry-point
// ─────────────────────────────────────────────────────────────────────────────

// PrintResults renders a fully populated ScanResult to stdout.
// Sections are rendered in logical order: identity → network → crypto → http.
func PrintResults(r *scanner.ScanResult) {
	renderScanHeader(r.Target)
	renderDNSSection(r.DNS)
	renderGeoIPSection(r.GeoIP)
	renderSSLSection(r.SSL)
	renderHTTPSection(r.Headers)
	renderSecuritySection(r.Headers)
	renderPortsSection(r.Ports)
	renderScanFooter()
}

// ─────────────────────────────────────────────────────────────────────────────
// Header / Footer
// ─────────────────────────────────────────────────────────────────────────────

func renderScanHeader(target string) {
	now := time.Now().Format("2006-01-02  15:04:05")
	content := fmt.Sprintf(
		"  %-12s%s\n  %-12s%s",
		"Target", pterm.LightCyan(pterm.Bold.Sprint(target)),
		"Timestamp", pterm.Gray(now),
	)
	_ = pterm.DefaultBox.
		WithTitle(pterm.Bold.Sprint("  ⬡  GOFETCH  ")).
		WithTitleTopCenter().
		Println(content)
	pterm.Println()
}

func renderScanFooter() {
	width := 56
	line := strings.Repeat("─", width)
	pterm.DefaultCenter.Println(pterm.Gray(line))
	pterm.DefaultCenter.Println(pterm.Gray("scan complete"))
	pterm.DefaultCenter.Println(pterm.Gray(line))
	pterm.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// Box helper — the core layout primitive
// ─────────────────────────────────────────────────────────────────────────────

// boxTable renders data as a pterm table, then wraps it in a titled box.
// The first row of data is treated as the header (bold, underlined by pterm).
// All value colouring must be pre-applied to the cell strings before calling.
func boxTable(title string, data pterm.TableData) {
	tableStr, err := pterm.DefaultTable.
		WithHasHeader(true).
		WithSeparator("   ").
		WithData(data).
		Srender()
	if err != nil || strings.TrimSpace(tableStr) == "" {
		tableStr = pterm.Gray("  (no data)")
	}
	_ = pterm.DefaultBox.
		WithTitle(pterm.LightCyan(pterm.Bold.Sprint(" " + title + " "))).
		WithTitleTopLeft().
		Println(tableStr)
	pterm.Println()
}

// errorBox renders a single-row error table inside a named box.
func errorBox(title, msg string) {
	boxTable(title, pterm.TableData{
		{"FIELD", "DETAIL"},
		{pterm.LightRed("error"), pterm.LightRed(msg)},
	})
}

// kv returns a two-cell [KEY, VALUE] row for identity tables.
// Keys are printed bold so they stand out from values.
func kv(key, val string) []string {
	return []string{pterm.Bold.Sprint(key), val}
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS
// ─────────────────────────────────────────────────────────────────────────────

func renderDNSSection(r *scanner.DNSResult) {
	const title = "DNS  RECORDS"
	if r == nil {
		errorBox(title, "result unavailable")
		return
	}

	data := pterm.TableData{
		{"TYPE", "VALUE"},
		kv("A  (IPv4)", joinCyan(r.ARecords, "  ·  ")),
		kv("AAAA  (IPv6)", joinCyan(r.AAAARecords, "  ·  ")),
		kv("CNAME", strCyan(r.CNAMERecord)),
		kv("MX", joinCyan(fmtMXSlice(r.MXRecords), "\n")),
		kv("TXT", joinCyan(r.TXTRecords, "\n")),
	}
	boxTable(title, data)

	if len(r.Errors) > 0 {
		for _, e := range r.Errors {
			pterm.Warning.Println(e)
		}
		pterm.Println()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GeoIP / Network
// ─────────────────────────────────────────────────────────────────────────────

func renderGeoIPSection(r *scanner.GeoIPResult) {
	const title = "GEO IP  /  NETWORK"
	if r == nil {
		errorBox(title, "result unavailable")
		return
	}
	if r.Error != "" {
		errorBox(title, r.Error)
		return
	}

	data := pterm.TableData{
		{"FIELD", "VALUE"},
		kv("IP Address", pterm.LightCyan(r.Query)),
		kv("Country", pterm.LightCyan(
			fmt.Sprintf("%s   (%s)", r.Country, r.CountryCode))),
		kv("Region / City", pterm.LightCyan(
			fmt.Sprintf("%s,  %s", r.RegionName, r.City))),
		kv("ISP", pterm.LightCyan(dashIfEmpty(r.ISP))),
		kv("Organisation", pterm.LightCyan(dashIfEmpty(r.Org))),
		kv("AS Number", pterm.LightCyan(dashIfEmpty(r.AS))),
		kv("Coordinates", pterm.Gray(
			fmt.Sprintf("%.4f °N,  %.4f °E", r.Lat, r.Lon))),
	}
	boxTable(title, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS / SSL
// ─────────────────────────────────────────────────────────────────────────────

func renderSSLSection(r *scanner.SSLResult) {
	const title = "TLS  /  SSL  CERTIFICATE"
	if r == nil {
		errorBox(title, "result unavailable")
		return
	}
	if r.Error != "" {
		errorBox(title, r.Error)
		return
	}

	expDate := r.ExpiresAt.Format("2006-01-02")
	var expiryCell string
	switch {
	case r.IsExpired:
		expiryCell = pterm.LightRed(
			fmt.Sprintf("✗  EXPIRED  (%s)", expDate))
	case r.DaysUntilExpiry < 14:
		expiryCell = pterm.LightRed(
			fmt.Sprintf("⚠  %s  —  %d days left", expDate, r.DaysUntilExpiry))
	case r.DaysUntilExpiry < 30:
		expiryCell = pterm.LightYellow(
			fmt.Sprintf("⚠  %s  —  %d days left", expDate, r.DaysUntilExpiry))
	default:
		expiryCell = pterm.LightGreen(
			fmt.Sprintf("✓  %s  —  %d days", expDate, r.DaysUntilExpiry))
	}

	data := pterm.TableData{
		{"FIELD", "VALUE"},
		kv("Subject (CN)", pterm.LightCyan(r.Subject)),
		kv("Issuer", pterm.LightCyan(r.Issuer)),
		kv("Issued", pterm.Gray(r.IssuedAt.Format("2006-01-02"))),
		kv("Expires", expiryCell),
		kv("SANs", joinCyan(r.SANs, "  ·  ")),
	}
	boxTable(title, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Response
// ─────────────────────────────────────────────────────────────────────────────

func renderHTTPSection(r *scanner.HeadersResult) {
	const title = "HTTP  RESPONSE"
	if r == nil {
		errorBox(title, "result unavailable")
		return
	}
	if r.Error != "" {
		errorBox(title, r.Error)
		return
	}

	statusStr := fmt.Sprintf("%d", r.StatusCode)
	var statusCell string
	switch {
	case r.StatusCode >= 500:
		statusCell = pterm.LightRed(statusStr + "  (server error)")
	case r.StatusCode >= 400:
		statusCell = pterm.LightYellow(statusStr + "  (client error)")
	case r.StatusCode >= 300:
		statusCell = pterm.LightCyan(statusStr + "  (redirect)")
	default:
		statusCell = pterm.LightGreen(statusStr + "  (ok)")
	}

	data := pterm.TableData{
		{"FIELD", "VALUE"},
		kv("Final URL", pterm.LightCyan(r.FinalURL)),
		kv("Status", statusCell),
		kv("Server", strCyan(r.Server)),
		kv("X-Powered-By", strCyan(r.XPoweredBy)),
	}
	boxTable(title, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Security Headers
// ─────────────────────────────────────────────────────────────────────────────

func renderSecuritySection(r *scanner.HeadersResult) {
	const title = "SECURITY  HEADERS"
	if r == nil || r.Error != "" {
		errorBox(title, "unavailable")
		return
	}

	sh := r.Security
	type hdr struct{ name, value string }
	headers := []hdr{
		{"Strict-Transport-Security", sh.StrictTransportSecurity},
		{"X-Frame-Options", sh.XFrameOptions},
		{"X-Content-Type-Options", sh.XContentTypeOptions},
		{"X-XSS-Protection", sh.XXSSProtection},
		{"Referrer-Policy", sh.ReferrerPolicy},
		{"Permissions-Policy", sh.PermissionsPolicy},
		{"Content-Security-Policy", sh.ContentSecurityPolicy},
	}

	data := pterm.TableData{{"HEADER", "STATUS", "VALUE"}}
	for _, h := range headers {
		var statusCell, valueCell string
		if h.value == "" {
			statusCell = pterm.LightRed("✗  MISSING")
			valueCell = pterm.Gray("—")
		} else {
			statusCell = pterm.LightGreen("✓  SET")
			val := h.value
			if len(val) > 54 {
				val = val[:54] + "…"
			}
			valueCell = pterm.LightGreen(val)
		}
		data = append(data, []string{
			pterm.Bold.Sprint(h.name),
			statusCell,
			valueCell,
		})
	}
	boxTable(title, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Scan
// ─────────────────────────────────────────────────────────────────────────────

func renderPortsSection(r *scanner.PortsResult) {
	const title = "PORT  SCAN"
	if r == nil {
		errorBox(title, "result unavailable")
		return
	}
	if r.Error != "" {
		errorBox(title, r.Error)
		return
	}

	// Summary line above the table.
	openCount := len(r.OpenPorts)
	closedCount := r.ScannedCount - openCount
	summary := fmt.Sprintf(
		"  Host %s   Checked %s   Open %s   Closed %s",
		pterm.LightCyan(r.ScannedIP),
		pterm.LightCyan(fmt.Sprintf("%d", r.ScannedCount)),
		pterm.LightGreen(fmt.Sprintf("%d", openCount)),
		pterm.Gray(fmt.Sprintf("%d", closedCount)),
	)
	pterm.Println(summary)
	pterm.Println()

	if openCount == 0 {
		boxTable(title, pterm.TableData{
			{"PORT", "SERVICE", "STATUS"},
			{"—", "—", pterm.LightYellow("no open ports in scanned range")},
		})
		return
	}

	data := pterm.TableData{{"PORT", "SERVICE", "STATUS"}}
	for _, op := range r.OpenPorts {
		data = append(data, []string{
			pterm.LightGreen(fmt.Sprintf("%d", op.Port)),
			pterm.LightCyan(op.Service),
			pterm.LightGreen("●  OPEN"),
		})
	}
	boxTable(title, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Cell value helpers
// ─────────────────────────────────────────────────────────────────────────────

// joinCyan colours each element cyan and joins them with sep.
// Returns a light-gray "(none)" when the slice is empty.
func joinCyan(ss []string, sep string) string {
	if len(ss) == 0 {
		return pterm.Gray("(none)")
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = pterm.LightCyan(s)
	}
	return strings.Join(out, pterm.Gray(sep))
}

// strCyan colours s cyan, or returns a gray "(none)" when empty.
func strCyan(s string) string {
	if s == "" {
		return pterm.Gray("(none)")
	}
	return pterm.LightCyan(s)
}

// dashIfEmpty returns "—" for empty strings (for fields that always exist
// but may be blank, like ISP/Org from GeoIP).
func dashIfEmpty(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// fmtMXSlice converts MXRecord structs to human-readable strings.
func fmtMXSlice(records []scanner.MXRecord) []string {
	out := make([]string, len(records))
	for i, mx := range records {
		out[i] = fmt.Sprintf("%s  (priority %d)", mx.Host, mx.Priority)
	}
	return out
}
