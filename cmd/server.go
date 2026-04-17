package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/api"
)

var (
	serverPort    int
	serverWorkers int
	serverAuthKey string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run ARGUS as an HTTP API daemon",
	Long: `Start the ARGUS API server, exposing scan submission, status,
and report retrieval over HTTP.

Endpoints:
  POST /api/v1/scan          Submit a new scan
  GET  /api/v1/scans/{id}    Check scan status
  GET  /api/v1/scans/{id}/report  Get full JSON report
  GET  /api/v1/health        Health check
  GET  /api/v1/rules         List loaded policies`,
	RunE: runServer,
}

func init() {
	serverCmd.Flags().IntVar(&serverPort, "port", 8443, "Port to listen on")
	serverCmd.Flags().IntVar(&serverWorkers, "workers", 4, "Maximum concurrent scans")
	serverCmd.Flags().StringVar(&serverAuthKey, "auth-key", "", "API key required in X-API-Key header (empty = no auth)")
	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	executor := api.NewExecutor(serverWorkers)
	srv := api.NewServer(serverPort, serverAuthKey, executor)

	// Listen for OS signals for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)
		cancel()
	}()

	return srv.ListenAndServe(ctx)
}
