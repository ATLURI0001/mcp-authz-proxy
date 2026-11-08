package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// Run against an isolated test database with deploy/schema.sql already applied.
func TestIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	ru := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || ru == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_REDIS_URL for real backend tests")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn, ru)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sub := "integration-test-subject"
	_, err = db.Pool.Exec(ctx, `INSERT INTO grants(subject,tool) VALUES($1,'echo') ON CONFLICT DO NOTHING`, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Exec(ctx, `DELETE FROM grants WHERE subject=$1`, sub)
	ok, err := db.Allow(ctx, sub, "echo")
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	ok, err = db.Allow(ctx, sub, "secret")
	if ok || err != nil {
		t.Fatal(ok, err)
	}
	if err = db.Audit(ctx, Event{ID: "integration-test", Subject: sub, Decision: "deny", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Exec(ctx, `DELETE FROM audit_events WHERE request_id='integration-test'`)
	token := "test-approval"
	hash := sha256.Sum256([]byte(token))
	hexHash := hex.EncodeToString(hash[:])
	_, err = db.Pool.Exec(ctx, `INSERT INTO approvals(token_hash,subject,digest,expires_at) VALUES($1,$2,'digest',now()+interval '1 minute') ON CONFLICT(token_hash) DO UPDATE SET expires_at=excluded.expires_at`, hexHash, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Exec(ctx, `DELETE FROM approvals WHERE token_hash=$1`, hexHash)
	ok, err = db.Consume(ctx, token, "wrong-user", "digest")
	if ok || err != nil {
		t.Fatal(ok, err)
	}
	ok, err = db.Consume(ctx, token, sub, "digest")
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	ok, err = db.Consume(ctx, token, sub, "digest")
	if ok || err != nil {
		t.Fatal(ok, err)
	}
	// Unique subjects avoid interference from prior runs in the same fixed window.
	rateSub := sub + t.TempDir()
	for i := 0; i < 3; i++ {
		ok, err = db.Limit(ctx, rateSub, 2)
		if err != nil || ok != (i < 2) {
			t.Fatal(i, ok, err)
		}
	}
}
