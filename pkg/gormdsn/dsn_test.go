package gormdsn

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewDBFromDSNSQLiteFormats(t *testing.T) {
	tests := map[string]string{
		"scheme":         "sqlite:file:",
		"absolute URL":   "sqlite://",
		"bare file path": "",
	}

	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "nanobot.db")
			db, err := NewDBFromDSN(prefix + databasePath)
			if err != nil {
				t.Fatalf("NewDBFromDSN: %v", err)
			}
			if err := db.Exec("CREATE TABLE test (id INTEGER PRIMARY KEY)").Error; err != nil {
				t.Fatalf("create table: %v", err)
			}
		})
	}

	t.Run("memory", func(t *testing.T) {
		db, err := NewDBFromDSN("sqlite::memory:")
		if err != nil {
			t.Fatalf("NewDBFromDSN: %v", err)
		}
		if err := db.Exec("CREATE TABLE test (id INTEGER PRIMARY KEY)").Error; err != nil {
			t.Fatalf("create table: %v", err)
		}
	})
}

// TestNewDBFromDSNLogsPlaceholdersNotBoundValues guards against a cleartext
// credential leak: sessions persist decrypted MCP config (bearer tokens and
// OAuth client secrets), and GORM interpolates bound values into the SQL it
// logs unless the logger is parameterized. A logged error is used here because
// it exercises the same value-substitution path as a slow-query log without
// depending on query timing.
func TestNewDBFromDSNLogsPlaceholdersNotBoundValues(t *testing.T) {
	const secret = "Bearer re_live_super_secret_value"

	var logOutput bytes.Buffer
	db, err := newDBFromDSN(":memory:", &logOutput)
	if err != nil {
		t.Fatalf("newDBFromDSN: %v", err)
	}

	type sample struct {
		ID    uint
		Value string
	}
	if err := db.AutoMigrate(&sample{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	if err := db.Create(&sample{ID: 1, Value: secret}).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := db.Create(&sample{ID: 1, Value: secret}).Error; err == nil {
		t.Fatal("expected a duplicate key error to force a logged query")
	}

	logged := logOutput.String()
	if strings.Contains(logged, secret) {
		t.Fatalf("bound value leaked into query log: %s", logged)
	}
	if !strings.Contains(logged, "?") {
		t.Fatalf("expected parameterized placeholders in query log, got: %s", logged)
	}
}
