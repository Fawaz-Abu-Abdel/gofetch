package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fawaz/gofetch/cmd"
	"github.com/fawaz/gofetch/internal/scanner"
)

// publicFS holds the embedded frontend assets compiled into the binary.
// The go:embed directive bundles everything under public/ at build time,
// so no separate static file serving or deployment step is needed.
//
//go:embed public/*
var publicFS embed.FS

func main() {
	// ── Mode detection ────────────────────────────────────────────────────────
	// CLI mode: any arguments are passed straight through to Cobra.
	// Web server mode: no arguments — used by Render and other PaaS hosts.
	if len(os.Args) > 1 {
		cmd.Execute()
		return
	}

	// ── Web server mode ───────────────────────────────────────────────────────
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Strip the "public" prefix so the embedded FS root is "/" not "/public/".
	frontendFS, err := fs.Sub(publicFS, "public")
	if err != nil {
		log.Fatalf("[gofetch] failed to create sub-filesystem: %v", err)
	}

	mux := http.NewServeMux()

	// Route "/" → embedded static files (index.html, etc.)
	mux.Handle("/", http.FileServer(http.FS(frontendFS)))

	// Route "/api/scan" → reconnaissance engine
	mux.HandleFunc("/api/scan", handleScan)

	// CRITICAL: bind to 0.0.0.0 (not localhost/127.0.0.1) so Render's
	// health-check probes can reach the process from outside the container.
	addr := "0.0.0.0:" + port
	log.Printf("[gofetch] web server listening → http://%s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[gofetch] server error: %v", err)
	}
}

// handleScan is the HTTP handler for the /api/scan endpoint.
// It accepts a single query parameter "domain", runs a full reconnaissance
// scan via scanner.Run(), and returns the structured result as JSON.
func handleScan(w http.ResponseWriter, r *http.Request) {
	// CORS headers — allow the frontend (and local dev proxies) to call freely.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Pre-flight check — browsers send this before the real request.
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "query parameter 'domain' is required",
		})
		return
	}

	log.Printf("[gofetch] scan requested → %s (remote: %s)", domain, r.RemoteAddr)

	result, err := scanner.Run(domain, false)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("[gofetch] JSON encode error: %v", err)
	}
}
