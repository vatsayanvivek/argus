package azure

// checkpoint.go implements scan checkpointing so that a partially completed
// scan can be resumed with `argus scan --resume <scan-id>` instead of being
// restarted from zero. This matters most for long-running Entra ID tenant
// enumeration (100k+ users) where a mid-scan Graph throttle would otherwise
// force the user to start over.
//
// Storage layout:
//
//     ~/.argus/scan-state/<scan-id>/
//         checkpoint.json        metadata (scan id, sub, tenant, started, per-service status)
//         resources.json         AzureResource + NetworkSnapshot from collectResources
//         identity.json          IdentitySnapshot + missing Graph scopes
//         rbac.json              []RoleAssignment from collectAzureRBAC
//         defender.json          findings + plans + secure score
//         activitylog.json       []ActivityEvent
//         policy.json            []PolicyResult
//
// Each sub-collector goroutine writes its result JSON on success. On resume,
// the goroutine first tries to read the JSON; on hit, it skips the upstream
// call entirely and feeds the cached result into the snapshot.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// CheckpointMeta is the top-level checkpoint file. It tracks which
// sub-collectors finished successfully. On resume, any service listed here
// as completed is skipped.
type CheckpointMeta struct {
	ScanID         string          `json:"scan_id"`
	SubscriptionID string          `json:"subscription_id"`
	TenantID       string          `json:"tenant_id"`
	StartedAt      time.Time       `json:"started_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Completed      map[string]bool `json:"completed"`
	ArgusVersion   string          `json:"argus_version,omitempty"`
}

// checkpointResources is the serialised form of the resources collector.
type checkpointResources struct {
	Resources []models.AzureResource  `json:"resources"`
	Network   models.NetworkSnapshot  `json:"network"`
}

type checkpointIdentity struct {
	Identity      models.IdentitySnapshot `json:"identity"`
	MissingScopes []string                `json:"missing_scopes"`
}

type checkpointDefender struct {
	Findings    []models.DefenderFinding `json:"findings"`
	Plans       map[string]string        `json:"plans"`
	SecureScore float64                  `json:"secure_score"`
}

// Checkpointer owns a state directory and serialises per-service results.
// A nil Checkpointer is safe — every method becomes a no-op. Use this to
// thread optional checkpointing through the collector without per-call
// nil checks at each goroutine.
type Checkpointer struct {
	Dir  string
	mu   sync.Mutex
	meta CheckpointMeta
}

// NewCheckpointer creates (or loads) a checkpoint directory for a scan id.
// If the directory already exists, its meta file is loaded so callers can
// inspect which services are already complete. The empty string disables
// checkpointing — the returned *Checkpointer is nil.
func NewCheckpointer(baseDir, scanID, subscriptionID, tenantID, version string) (*Checkpointer, error) {
	if baseDir == "" || scanID == "" {
		return nil, nil
	}
	dir := filepath.Join(baseDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("checkpoint: mkdir: %w", err)
	}

	cp := &Checkpointer{
		Dir: dir,
		meta: CheckpointMeta{
			ScanID:         scanID,
			SubscriptionID: subscriptionID,
			TenantID:       tenantID,
			StartedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
			Completed:      map[string]bool{},
			ArgusVersion:   version,
		},
	}

	// Merge any existing meta file — resume path.
	metaPath := filepath.Join(dir, "checkpoint.json")
	if raw, err := os.ReadFile(metaPath); err == nil {
		var existing CheckpointMeta
		if err := json.Unmarshal(raw, &existing); err == nil && existing.ScanID == scanID {
			// Same-scan resume: inherit completion state + start time.
			cp.meta.StartedAt = existing.StartedAt
			cp.meta.Completed = existing.Completed
			if cp.meta.Completed == nil {
				cp.meta.Completed = map[string]bool{}
			}
		}
	}

	if err := cp.writeMeta(); err != nil {
		return nil, err
	}
	return cp, nil
}

// IsDone reports whether a named service already has a complete checkpoint
// on disk. Safe to call on a nil receiver.
func (c *Checkpointer) IsDone(service string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.meta.Completed[service]
}

// Save writes a service result to disk and marks the service as complete.
// The service name must match the sub-collector's canonical name:
// "resources" | "identity" | "rbac" | "defender" | "activitylog" | "policy".
func (c *Checkpointer) Save(service string, payload interface{}) error {
	if c == nil {
		return nil
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint %s: marshal: %w", service, err)
	}
	p := filepath.Join(c.Dir, service+".json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		return fmt.Errorf("checkpoint %s: write: %w", service, err)
	}
	c.mu.Lock()
	c.meta.Completed[service] = true
	c.meta.UpdatedAt = time.Now().UTC()
	c.mu.Unlock()
	return c.writeMeta()
}

// Load reads the cached JSON for a service into dest. Returns os.ErrNotExist
// when the service hasn't been checkpointed yet.
func (c *Checkpointer) Load(service string, dest interface{}) error {
	if c == nil {
		return os.ErrNotExist
	}
	p := filepath.Join(c.Dir, service+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

// writeMeta atomically flushes the meta file. Callers hold their own locks
// when they modify cp.meta; writeMeta takes its own lock for the copy to
// avoid blocking other goroutines during the write.
func (c *Checkpointer) writeMeta() error {
	c.mu.Lock()
	snapshot := c.meta
	c.mu.Unlock()

	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(c.Dir, "checkpoint.json")
	// Atomic swap: write tmp, then rename.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Remove deletes the checkpoint directory. Called after a scan completes
// successfully so stale state doesn't accumulate.
func (c *Checkpointer) Remove() error {
	if c == nil || c.Dir == "" {
		return nil
	}
	return os.RemoveAll(c.Dir)
}

// ListResumable enumerates every scan checkpoint in a base dir along with
// its last-updated timestamp and completion status. Designed for
// `argus scan --list-resumable`.
type ResumableScan struct {
	ScanID         string
	SubscriptionID string
	TenantID       string
	StartedAt      time.Time
	UpdatedAt      time.Time
	Completed      []string
	Missing        []string
}

var allServices = []string{"resources", "identity", "rbac", "defender", "activitylog", "policy"}

func ListResumable(baseDir string) ([]ResumableScan, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := []ResumableScan{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(baseDir, e.Name(), "checkpoint.json")
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var m CheckpointMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		scan := ResumableScan{
			ScanID:         m.ScanID,
			SubscriptionID: m.SubscriptionID,
			TenantID:       m.TenantID,
			StartedAt:      m.StartedAt,
			UpdatedAt:      m.UpdatedAt,
		}
		for _, s := range allServices {
			if m.Completed[s] {
				scan.Completed = append(scan.Completed, s)
			} else {
				scan.Missing = append(scan.Missing, s)
			}
		}
		// Only surface scans that are actually incomplete — a scan with
		// every service completed has nothing to resume.
		if len(scan.Missing) > 0 {
			out = append(out, scan)
		}
	}
	return out, nil
}
