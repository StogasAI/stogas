//go:build cgo && stogas_gateway

package stogas

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// The shared vectors' rows hash to their leaves, and their batch seals under the same key.
func TestLogBatchesSealTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../tests/fixtures/log-batch-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Rows   []json.RawMessage
		Leaves []string
		Batch  map[string]any
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	leaves := make([]LogLeaf, len(vectors.Rows))
	for i, row := range vectors.Rows {
		// Whitespace and key order do not change a leaf.
		var indented bytes.Buffer
		if err := json.Indent(&indented, row, "", "  "); err != nil {
			t.Fatal(err)
		}
		if leaves[i], err = LogRowLeaf(indented.Bytes()); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(leaves[i][:]); got != vectors.Leaves[i] {
			t.Fatalf("leaf %d = %s, want %s", i, got, vectors.Leaves[i])
		}
	}
	for _, row := range []string{`[]`, `{"a":1,"a":2}`, `{"a":9007199254740993}`, `{`} {
		if _, err := LogRowLeaf([]byte(row)); !errors.Is(err, ErrGatewayInput) {
			t.Fatalf("LogRowLeaf(%s) = %v", row, err)
		}
	}

	keys, err := GenerateNodeKeys(bytes.NewReader(bytes.Join([][]byte{
		bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32),
	}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	var boot [32]byte
	if _, err := hex.Decode(boot[:], []byte(vectors.Batch["boot_sha256"].(string))); err != nil {
		t.Fatal(err)
	}
	node := vectors.Batch["node_id"].(string)
	opened, sealed := time.UnixMilli(1_793_694_840_000), time.UnixMilli(1_793_694_900_004)
	signed, err := keys.SignLogBatch(boot, node, 12, opened, sealed, leaves)
	if err != nil {
		t.Fatal(err)
	}
	var batch map[string]any
	if err := json.Unmarshal(signed, &batch); err != nil {
		t.Fatal(err)
	}
	// Signatures are randomized, so only their length is fixed.
	if signature, _ := batch["signature"].(string); len(signature) != 4498 {
		t.Fatalf("signature has %d characters", len(signature))
	}
	batch["signature"] = vectors.Batch["signature"]
	if got, want := mustJSON(t, batch), mustJSON(t, vectors.Batch); got != want {
		t.Fatalf("batch = %s, want %s", got, want)
	}

	for name, sign := range map[string]func() ([]byte, error){
		"empty": func() ([]byte, error) { return keys.SignLogBatch(boot, node, 12, opened, sealed, nil) },
		"too large": func() ([]byte, error) {
			return keys.SignLogBatch(boot, node, 12, opened, sealed, make([]LogLeaf, MaxLogBatchLeaves+1))
		},
		"unnumbered": func() ([]byte, error) { return keys.SignLogBatch(boot, node, 0, opened, sealed, leaves) },
		"reversed":   func() ([]byte, error) { return keys.SignLogBatch(boot, node, 12, sealed, opened, leaves) },
		"unnamed":    func() ([]byte, error) { return keys.SignLogBatch(boot, "", 12, opened, sealed, leaves) },
	} {
		if _, err := sign(); !errors.Is(err, ErrGatewayInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	keys.Close()
	if _, err := keys.SignLogBatch(boot, node, 12, opened, sealed, leaves); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed keys: %v", err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
