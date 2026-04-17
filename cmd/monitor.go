package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vatsayanvivek/argus/internal/config"
	"github.com/vatsayanvivek/argus/internal/monitor"
)

var (
	monitorTenant         string
	monitorSubscription   string
	monitorInterval       time.Duration
	monitorConfigPath     string
	monitorWebhookOnDrift bool
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Continuously scan Azure subscriptions and report score drift",
	Long: `Run ARGUS in continuous monitoring mode. The monitor polls Azure
subscriptions at a fixed interval, evaluates all policies, computes
attack chains, and compares the security score against the previous
scan cycle. When --webhook-on-drift is enabled, webhooks fire
whenever the score changes by more than 5 points.

Examples:
  # Monitor a single subscription every 4 hours
  argus monitor --tenant <TENANT_ID> --subscription <SUB_ID>

  # Monitor all subscriptions with webhook drift alerts
  argus monitor --tenant <TENANT_ID> --interval 2h --webhook-on-drift

  # Use a custom config file
  argus monitor --tenant <TENANT_ID> --config ./argus.yaml`,
	RunE: runMonitor,
}

func init() {
	monitorCmd.Flags().StringVar(&monitorTenant, "tenant", "", "Azure tenant ID (required)")
	monitorCmd.Flags().StringVar(&monitorSubscription, "subscription", "", "Azure subscription ID (omit to monitor all subscriptions)")
	monitorCmd.Flags().DurationVar(&monitorInterval, "interval", 4*time.Hour, "Scan interval (e.g. 2h, 30m)")
	monitorCmd.Flags().StringVar(&monitorConfigPath, "config", "", "Path to ARGUS config file")
	monitorCmd.Flags().BoolVar(&monitorWebhookOnDrift, "webhook-on-drift", false, "Send webhook when score changes by >5 points")
	_ = monitorCmd.MarkFlagRequired("tenant")
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// Load config.
	var cfg *config.Config
	if monitorConfigPath != "" {
		var err error
		cfg, err = config.LoadConfig(monitorConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v\n", err)
		}
	}

	mon := &monitor.Monitor{
		TenantID:       monitorTenant,
		SubscriptionID: monitorSubscription,
		Interval:       monitorInterval,
		WebhookOnDrift: monitorWebhookOnDrift,
		Config:         cfg,
	}

	scope := monitorSubscription
	if scope == "" {
		scope = "all subscriptions"
	}
	fmt.Printf("ARGUS continuous monitor starting\n")
	fmt.Printf("  Tenant:       %s\n", monitorTenant)
	fmt.Printf("  Scope:        %s\n", scope)
	fmt.Printf("  Interval:     %s\n", monitorInterval)
	fmt.Printf("  Drift alerts: %v\n\n", monitorWebhookOnDrift)

	// Set up context that cancels on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := mon.Run(ctx); err != nil {
		return err
	}

	fmt.Println("\nMonitor stopped.")
	return nil
}
