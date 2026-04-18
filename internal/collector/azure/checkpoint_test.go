package azure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

func TestCheckpointer_SaveLoadListRemove(t *testing.T) {
	base := t.TempDir()

	cp, err := NewCheckpointer(base, "scan-test-01", "sub-1", "tenant-1", "1.0.0")
	if err != nil {
		t.Fatalf("NewCheckpointer: %v", err)
	}
	if cp == nil {
		t.Fatal("expected non-nil checkpointer")
	}

	// No service done yet.
	if cp.IsDone("identity") {
		t.Error("freshly created checkpointer should not report any service as done")
	}

	// Save an identity result.
	identity := checkpointIdentity{
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{
				{ID: "u1", DisplayName: "alice"},
			},
		},
		MissingScopes: []string{"Directory.Read.All"},
	}
	if err := cp.Save("identity", identity); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !cp.IsDone("identity") {
		t.Error("after Save identity, IsDone should be true")
	}

	// Load it back.
	var round checkpointIdentity
	if err := cp.Load("identity", &round); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(round.Identity.Users) != 1 || round.Identity.Users[0].DisplayName != "alice" {
		t.Errorf("Load returned unexpected shape: %+v", round)
	}
	if len(round.MissingScopes) != 1 || round.MissingScopes[0] != "Directory.Read.All" {
		t.Errorf("Load did not round-trip missing scopes: %+v", round.MissingScopes)
	}

	// ListResumable should include the scan since 5/6 services are pending.
	scans, err := ListResumable(base)
	if err != nil {
		t.Fatalf("ListResumable: %v", err)
	}
	if len(scans) != 1 || scans[0].ScanID != "scan-test-01" {
		t.Fatalf("ListResumable: expected 1 scan named scan-test-01, got %+v", scans)
	}
	if len(scans[0].Completed) != 1 || scans[0].Completed[0] != "identity" {
		t.Errorf("ListResumable.Completed: expected [identity], got %v", scans[0].Completed)
	}

	// Second instance on same scan id should see identity as already-done
	// (resume path).
	cp2, err := NewCheckpointer(base, "scan-test-01", "sub-1", "tenant-1", "1.0.0")
	if err != nil {
		t.Fatalf("NewCheckpointer resume: %v", err)
	}
	if !cp2.IsDone("identity") {
		t.Error("resumed checkpointer should see identity as done")
	}

	// Complete every service, then ListResumable should drop the scan.
	for _, s := range []string{"resources", "rbac", "defender", "activitylog", "policy"} {
		if err := cp2.Save(s, []int{}); err != nil {
			t.Fatalf("Save %s: %v", s, err)
		}
	}
	scans2, _ := ListResumable(base)
	if len(scans2) != 0 {
		t.Errorf("after all services completed, ListResumable should be empty, got %+v", scans2)
	}

	// Remove cleans up the directory.
	if err := cp2.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "scan-test-01")); !os.IsNotExist(err) {
		t.Errorf("expected scan dir to be deleted, stat err = %v", err)
	}
}

func TestCheckpointer_NilSafe(t *testing.T) {
	var cp *Checkpointer
	if cp.IsDone("anything") {
		t.Error("nil checkpointer should return false from IsDone")
	}
	if err := cp.Save("x", struct{}{}); err != nil {
		t.Errorf("nil checkpointer Save should be a no-op, got %v", err)
	}
	if err := cp.Remove(); err != nil {
		t.Errorf("nil checkpointer Remove should be a no-op, got %v", err)
	}
	// Load on nil must fail with ErrNotExist so callers fall through.
	if err := cp.Load("x", &struct{}{}); !os.IsNotExist(err) {
		t.Errorf("nil checkpointer Load should return ErrNotExist, got %v", err)
	}
}

func TestNewCheckpointer_EmptyDirDisablesCheckpointing(t *testing.T) {
	cp, err := NewCheckpointer("", "scan-x", "sub", "tenant", "1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp != nil {
		t.Errorf("empty base dir should disable checkpointing, got %+v", cp)
	}
}
