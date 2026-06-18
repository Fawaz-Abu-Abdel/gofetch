package cmd

import (
	"os"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

// rootCmd is the base command. When run without subcommands it prints the banner.
var rootCmd = &cobra.Command{
	Use:   "gofetch",
	Short: "A modular OSINT/Network Reconnaissance CLI tool",
	Long: `gofetch is a fast, modular CLI tool for OSINT and network reconnaissance.
Run 'gofetch scan <domain|url>' to begin target enumeration.`,
	// When called with no subcommand, display the banner + usage hint.
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		pterm.Println()
		pterm.Info.Println("Run 'gofetch scan <domain|url>' to start reconnaissance.")
		pterm.Info.Println("Run 'gofetch --help' for a full list of commands.")
	},
}

// Execute is the entry-point called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		pterm.Error.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Global persistent flags go here.
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// Register subcommands.
	rootCmd.AddCommand(scanCmd)
}

// printBanner renders a retro-style ASCII art banner using pterm.
func printBanner() {
	// BigText uses a built-in ASCII font for large block letters.
	bannerText, _ := pterm.DefaultBigText.
		WithLetters(
			pterm.NewLettersFromStringWithStyle("GO", pterm.NewStyle(pterm.FgCyan)),
			pterm.NewLettersFromStringWithStyle("FETCH", pterm.NewStyle(pterm.FgMagenta)),
		).
		Srender()

	pterm.Println(bannerText)

	// Subtitle / tagline beneath the banner.
	pterm.DefaultCenter.WithCenterEachLineSeparately().Print(
		pterm.LightCyan("╔══════════════════════════════════════════════╗\n") +
			pterm.LightMagenta("     OSINT & Network Intelligence Toolkit     \n") +
			pterm.LightCyan("╚══════════════════════════════════════════════╝"),
	)
}
