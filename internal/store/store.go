package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Event struct {
	ID       string `json:"id"`
	Subject  string `json:"subject,omitempty"`
	Method   string `json:"method,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}
type Backend interface {
	Allow(context.Context, string, string) (bool, error)
	Audit(context.Context, Event) error
	Limit(context.Context, string, int) (bool, error)
	Consume(context.Context, string, string, string) (bool, error)
	Ready(context.Context) error
}
type DB struct {
	Pool  *pgxpool.Pool
	Redis *redis.Client
}

func Open(ctx context.Context, dsn, redisURL string) (*DB, error) {
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	o, err := redis.ParseURL(redisURL)
	if err != nil {
		p.Close()
		return nil, err
	}
	d := &DB{p, redis.NewClient(o)}
	if err = d.Ready(ctx); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}
func (d *DB) Close() { d.Pool.Close(); _ = d.Redis.Close() }
func (d *DB) Ready(ctx context.Context) error {
	if err := d.Pool.Ping(ctx); err != nil {
		return err
	}
	return d.Redis.Ping(ctx).Err()
}
func (d *DB) Allow(ctx context.Context, sub, tool string) (bool, error) {
	var ok bool
	err := d.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM grants WHERE subject=$1 AND tool=$2)`, sub, tool).Scan(&ok)
	return ok, err
}
func (d *DB) Audit(ctx context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = d.Pool.Exec(ctx, `INSERT INTO audit_events(request_id,event) VALUES($1,$2)`, e.ID, b)
	return err
}

var limiter = redis.NewScript(`local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],120) end; return n`)

func (d *DB) Limit(ctx context.Context, sub string, max int) (bool, error) {
	h := sha256.Sum256([]byte(sub))
	key := fmt.Sprintf("mcp:limit:%x:%d", h, time.Now().Unix()/60)
	n, err := limiter.Run(ctx, d.Redis, []string{key}).Int64()
	return n <= int64(max), err
}
func (d *DB) Consume(ctx context.Context, token, sub, digest string) (bool, error) {
	h := sha256.Sum256([]byte(token))
	tag, err := d.Pool.Exec(ctx, `DELETE FROM approvals WHERE token_hash=$1 AND subject=$2 AND digest=$3 AND expires_at>now()`, hex.EncodeToString(h[:]), sub, digest)
	return tag.RowsAffected() == 1, err
}
