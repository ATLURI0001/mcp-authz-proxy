package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunArgs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		dsn     string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{},
			dsn:     "postgres://test",
			wantErr: "usage: admin",
		},
		{
			name:    "unknown command",
			args:    []string{"destroy", "-subject", "s1", "-tool", "t1"},
			dsn:     "postgres://test",
			wantErr: "unknown command",
		},
		{
			name:    "grant missing subject",
			args:    []string{"grant", "-tool", "echo"},
			dsn:     "postgres://test",
			wantErr: "subject and tool required",
		},
		{
			name:    "grant missing tool",
			args:    []string{"grant", "-subject", "alice"},
			dsn:     "postgres://test",
			wantErr: "subject and tool required",
		},
		{
			name:    "revoke missing tool",
			args:    []string{"revoke", "-subject", "alice"},
			dsn:     "postgres://test",
			wantErr: "subject and tool required",
		},
		{
			name:    "approve missing subject",
			args:    []string{"approve", "-tool", "echo", "-params", "p.json"},
			dsn:     "postgres://test",
			wantErr: "subject and tool required",
		},
		{
			name:    "approve missing params",
			args:    []string{"approve", "-subject", "alice", "-tool", "echo"},
			dsn:     "postgres://test",
			wantErr: "params file required for approve",
		},
		{
			name:    "missing database url on list",
			args:    []string{"list", "-subject", "alice"},
			dsn:     "",
			wantErr: "DATABASE_URL required",
		},
		{
			name:    "missing database url on grant",
			args:    []string{"grant", "-subject", "alice", "-tool", "echo"},
			dsn:     "",
			wantErr: "DATABASE_URL required",
		},
		{
			name:    "approve ttl too low",
			args:    []string{"approve", "-subject", "alice", "-tool", "echo", "-params", "p.json", "-ttl", "30s"},
			dsn:     "postgres://test",
			wantErr: "ttl must be between 1 minute and 24 hours",
		},
		{
			name:    "approve ttl too high",
			args:    []string{"approve", "-subject", "alice", "-tool", "echo", "-params", "p.json", "-ttl", "48h"},
			dsn:     "postgres://test",
			wantErr: "ttl must be between 1 minute and 24 hours",
		},
		{
			name:    "approve negative ttl",
			args:    []string{"approve", "-subject", "alice", "-tool", "echo", "-params", "p.json", "-ttl", "-5m"},
			dsn:     "postgres://test",
			wantErr: "ttl must be between 1 minute and 24 hours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runArgs(tt.args, &out, tt.dsn)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestRunArgs_ApproveToolMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	paramsFile := filepath.Join(tmpDir, "params.json")
	if err := os.WriteFile(paramsFile, []byte(`{"name":"restart_demo","arguments":{}}`), 0600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := runArgs([]string{"approve", "-subject", "alice", "-tool", "echo", "-params", paramsFile}, &out, "postgres://fake")
	if err == nil {
		t.Fatal("expected tool mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "params tool does not match -tool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunArgs_ApproveFileNotFound(t *testing.T) {
	var out bytes.Buffer
	err := runArgs([]string{"approve", "-subject", "alice", "-tool", "echo", "-params", "non_existent_file.json"}, &out, "postgres://fake")
	if err == nil {
		t.Fatal("expected file not found error, got nil")
	}
}
