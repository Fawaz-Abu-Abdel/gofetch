package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// CommonPorts is the default set scanned when the caller passes nil.
// Covers the most operationally significant TCP services.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 465,
	587, 993, 995, 1433, 1521, 3000, 3306, 3389,
	5432, 5900, 6379, 8080, 8443, 8888, 27017,
}

// portServices maps well-known port numbers to human-readable service names.
var portServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP/TLS",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle DB",
	3000:  "Dev/Node",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	27017: "MongoDB",
}

// ServiceName returns the well-known service name for a port, or "unknown".
func ServiceName(port int) string {
	if name, ok := portServices[port]; ok {
		return name
	}
	return "unknown"
}

// OpenPort pairs a port number with its resolved service name.
type OpenPort struct {
	Port    int
	Service string
}

// PortsResult contains the outcome of a concurrent TCP port scan.
type PortsResult struct {
	ScannedIP    string
	ScannedCount int
	OpenPorts    []OpenPort // sorted ascending by port number
	Error        string
}

// probeResult is the internal message passed from each port goroutine.
type probeResult struct {
	port int
	open bool
}

// ScanPorts concurrently attempts TCP connections to each port in ports against
// ip, using a 1-second dial timeout per attempt. Pass nil for ports to use
// CommonPorts. Returns results sorted by port number.
func ScanPorts(ip string, ports []int) *PortsResult {
	if ports == nil {
		ports = CommonPorts
	}

	result := &PortsResult{
		ScannedIP:    ip,
		ScannedCount: len(ports),
	}

	if ip == "" {
		result.Error = "no IP address provided"
		return result
	}

	// Buffered channel absorbs all results without goroutines blocking on send.
	ch := make(chan probeResult, len(ports))

	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err == nil {
				conn.Close()
				ch <- probeResult{port: p, open: true}
			} else {
				ch <- probeResult{port: p, open: false}
			}
		}(port)
	}

	// Close the channel once every goroutine has sent its result.
	// This runs in a separate goroutine so we don't block while draining ch.
	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.open {
			result.OpenPorts = append(result.OpenPorts, OpenPort{
				Port:    r.port,
				Service: ServiceName(r.port),
			})
		}
	}

	// Guarantee deterministic ordering regardless of goroutine scheduling.
	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Port < result.OpenPorts[j].Port
	})

	return result
}
