package cmd

// serve.go registers `argus serve` — a local-only HTTP dashboard that reads
// scan JSON from a directory and presents findings, chains, attack graph,
// drift, and history views. No SaaS, no telemetry, no login. Customers run
// it in their own environment; data never leaves disk.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/server"
)

var (
	serveAddr    string
	serveScanDir string
	serveOpen    bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local dashboard for browsing scan results",
	Long: `Serve opens a local-only web dashboard on localhost for browsing scan
results, attack chains, compliance posture, and scan-to-scan drift.

  argus serve                     # dashboard at http://localhost:8080
  argus serve --addr :9000        # custom port
  argus serve --scan-dir ./runs   # point at a different output dir

The dashboard reads scan JSON files from the --scan-dir directory. Run
` + "`argus scan --output json`" + ` first to produce input for the dashboard.

Nothing leaves your machine. No telemetry. No CDN. All assets embed.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:8080", "Listen address (127.0.0.1:PORT — loopback only by default)")
	serveCmd.Flags().StringVar(&serveScanDir, "scan-dir", "./argus-output", "Directory containing argus_*.json scan files")
	serveCmd.Flags().BoolVar(&serveOpen, "open", false, "Open the dashboard in the default browser")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	if _, err := os.Stat(serveScanDir); os.IsNotExist(err) {
		fmt.Printf("Note: scan directory %s does not exist yet. Running `argus scan` first will populate it.\n", serveScanDir)
		if err := os.MkdirAll(serveScanDir, 0o755); err != nil {
			return fmt.Errorf("create scan dir: %w", err)
		}
	}

	srv, err := server.New(server.Config{
		Addr:    serveAddr,
		ScanDir: serveScanDir,
	})
	if err != nil {
		return err
	}
	return srv.Run()
}
