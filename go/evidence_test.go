//go:build cgo

package stogas

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestEvidenceConfigurationFailsClosed(t *testing.T) {
	for _, options := range []EvidenceOptions{
		{Environment: "unknown"},
		{Environment: "prod", Root: &TrustRoot{KeyID: "invalid", PublicKey: "invalid", RekorPublicKey: "invalid"}},
	} {
		owner, err := NewEvidence(options)
		if owner != nil || err == nil {
			t.Fatalf("unexpected evidence construction: %v, %v", owner, err)
		}
		var failure *VerificationError
		if !errors.As(err, &failure) || failure.Code == "" {
			t.Fatalf("missing structured reason: %v", err)
		}
	}
}

func TestTrustRootKeepsItsRekorV2Scope(t *testing.T) {
	bytes, err := os.ReadFile("../tests/fixtures/hardware-session-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Root TrustRoot `json:"root"`
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	scope := RekorV2Scope{
		FirstIndexes: map[string]uint64{"log2025-1.rekor.sigstore.dev": 1},
		OpenedFrom:   "2026-10-31T00:00:00Z",
	}
	root := fixture.Root
	root.RekorV2 = &scope
	owner, err := NewEvidence(EvidenceOptions{Environment: "prod", Root: &root})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// The scope reaches the core, which rejects an invalid one.
	invalid := scope
	invalid.OpenedFrom = "2026-10-31"
	root.RekorV2 = &invalid
	if owner, err := NewEvidence(EvidenceOptions{Environment: "prod", Root: &root}); owner != nil || err == nil {
		t.Fatalf("accepted an invalid Rekor v2 scope: %v, %v", owner, err)
	}
}
