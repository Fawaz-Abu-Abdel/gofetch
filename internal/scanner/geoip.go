package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GeoIPResult holds geolocation and network metadata for an IP address
// sourced from the ip-api.com free JSON API.
type GeoIPResult struct {
	// API-populated fields (JSON tags must match ip-api.com's field names exactly).
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Message     string  `json:"message"` // populated on API failure (e.g. "private range")
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"` // e.g. "AS13335 Cloudflare, Inc."
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`

	// Error is non-empty when the HTTP request or JSON decode failed.
	// Distinct from Message, which is an API-level failure reason.
	Error string `json:"-"`
}

// geoIPEndpoint is the ip-api.com JSON endpoint.
// The fields query param minimises response payload.
const geoIPEndpoint = "http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,query"

// GetGeoIP queries ip-api.com for geolocation and network metadata about ip.
// ip must be a routable IPv4 or IPv6 address; private ranges return an API error.
func GetGeoIP(ip string) *GeoIPResult {
	result := &GeoIPResult{Query: ip}

	if ip == "" {
		result.Error = "no IP address provided"
		return result
	}

	client := &http.Client{Timeout: 8 * time.Second}
	url := fmt.Sprintf(geoIPEndpoint, ip)

	resp, err := client.Get(url)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		result.Error = fmt.Sprintf("JSON decode failed: %v", err)
		return result
	}

	// ip-api.com signals failures via the "status" field rather than HTTP codes.
	if result.Status != "success" {
		msg := result.Message
		if msg == "" {
			msg = "unknown API error"
		}
		result.Error = fmt.Sprintf("API error: %s", msg)
	}

	return result
}
