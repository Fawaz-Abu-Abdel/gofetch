package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fawaz/gofetch/internal/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	traceCount int
)

// traceCmd represents the trace subcommand
var traceCmd = &cobra.Command{
	Use:   "trace <url|domain>",
	Short: "Benchmarking request latency phases with net/http/httptrace",
	Long: `trace conducts high-precision benchmark runs on HTTP connection phases.
It resolves and tracks timings for DNS, TCP, TLS handshakes, TTFB, and Transfer rates.`,
	Args: cobra.ExactArgs(1),
	Run:  runTrace,
}

func runTrace(cmd *cobra.Command, args []string) {
	target := args[0]

	pterm.Println()
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgCyan)).WithTextStyle(pterm.NewStyle(pterm.FgBlack)).Println("  GOFETCH TRACE BENCHMARK  ")
	pterm.Println()
	pterm.Info.Printfln("Target     : %s", pterm.LightCyan(target))
	pterm.Info.Printfln("Iterations : %d iterations", traceCount)
	pterm.Println()

	spinner, _ := pterm.DefaultSpinner.
		WithText(fmt.Sprintf("Conducting benchmark iterations (0/%d)...", traceCount)).
		Start()

	// Update text as iterations execute
	go func() {
		for i := 0; i < traceCount; i++ {
			time.Sleep(350 * time.Millisecond) // approximate buffer spacing
			spinner.UpdateText(fmt.Sprintf("Conducting benchmark iterations (%d/%d)...", i+1, traceCount))
		}
	}()

	summary, err := scanner.TraceURL(target, traceCount)
	if err != nil {
		spinner.Fail(fmt.Sprintf("Benchmark trace failed: %v", err))
		os.Exit(1)
	}

	spinner.Success("Trace benchmark completed")
	pterm.Println()

	renderTraceTable(summary)
}

func renderTraceTable(s *scanner.TraceSummary) {
	// Status checks and latency evaluation helpers
	checkStatus := func(name string, avg time.Duration, limit time.Duration) string {
		if avg == 0 {
			return pterm.Gray("N/A")
		}
		if avg > limit {
			return pterm.Yellow(fmt.Sprintf("Slow (limit %v)", limit))
		}
		return pterm.Green("Optimal")
	}

	tableData := pterm.TableData{
		{"METRIC PHASE", "MIN VALUE", "MAX VALUE", "AVERAGE", "ASSESSMENT"},
		{
			pterm.Bold.Sprint("DNS Lookup"),
			fmtDuration(s.DNSLookup.Min),
			fmtDuration(s.DNSLookup.Max),
			fmtDuration(s.DNSLookup.Avg),
			checkStatus("DNS", s.DNSLookup.Avg, 100*time.Millisecond),
		},
		{
			pterm.Bold.Sprint("TCP Connection"),
			fmtDuration(s.TCPConnection.Min),
			fmtDuration(s.TCPConnection.Max),
			fmtDuration(s.TCPConnection.Avg),
			checkStatus("TCP", s.TCPConnection.Avg, 150*time.Millisecond),
		},
		{
			pterm.Bold.Sprint("TLS Handshake"),
			fmtDuration(s.TLSHandshake.Min),
			fmtDuration(s.TLSHandshake.Max),
			fmtDuration(s.TLSHandshake.Avg),
			checkStatus("TLS", s.TLSHandshake.Avg, 200*time.Millisecond),
		},
		{
			pterm.Bold.Sprint("Server Processing (TTFB)"),
			fmtDuration(s.ServerProcess.Min),
			fmtDuration(s.ServerProcess.Max),
			fmtDuration(s.ServerProcess.Avg),
			checkStatus("TTFB", s.ServerProcess.Avg, 400*time.Millisecond),
		},
		{
			pterm.Bold.Sprint("Content Transfer"),
			fmtDuration(s.ContentTransfer.Min),
			fmtDuration(s.ContentTransfer.Max),
			fmtDuration(s.ContentTransfer.Avg),
			checkStatus("Transfer", s.ContentTransfer.Avg, 300*time.Millisecond),
		},
		{
			pterm.Bold.Sprint("Total Duration"),
			fmtDuration(s.TotalTime.Min),
			fmtDuration(s.TotalTime.Max),
			fmtDuration(s.TotalTime.Avg),
			checkStatus("Total", s.TotalTime.Avg, 1200*time.Millisecond),
		},
	}

	_ = pterm.DefaultTable.
		WithHasHeader(true).
		WithSeparator("   ").
		WithData(tableData).
		Render()

	pterm.Println()
}

func fmtDuration(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f ms", float64(d.Microseconds())/1000.0)
}

func init() {
	traceCmd.Flags().IntVarP(&traceCount, "count", "c", 3, "Number of benchmarking iteration runs")
	rootCmd.AddCommand(traceCmd)
}
