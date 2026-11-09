// admin is an operator-only CLI; its database credentials confer administrative power.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ATLURI0001/mcp-authz-proxy/internal/gateway"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	return runArgs(os.Args[1:], os.Stdout, os.Getenv("DATABASE_URL"))
}

func runArgs(args []string, stdout io.Writer, dsn string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: admin grant|revoke|list|approve -subject UUID -tool NAME [-params file.json]")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sub := fs.String("subject", "", "exact issuer subject")
	tool := fs.String("tool", "", "tool name")
	params := fs.String("params", "", "complete tools/call params JSON file")
	ttl := fs.Duration("ttl", 5*time.Minute, "approval token lifetime (default 5m, min 1m, max 24h)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch cmd {
	case "grant", "revoke":
		if *sub == "" || *tool == "" {
			return fmt.Errorf("subject and tool required")
		}
	case "approve":
		if *sub == "" || *tool == "" {
			return fmt.Errorf("subject and tool required")
		}
		if *params == "" {
			return fmt.Errorf("params file required for approve")
		}
		if *ttl < 1*time.Minute || *ttl > 24*time.Hour {
			return fmt.Errorf("ttl must be between 1 minute and 24 hours")
		}
	case "list":
		// subject and tool are optional filters
	default:
		return fmt.Errorf("unknown command")
	}

	if dsn == "" {
		return fmt.Errorf("DATABASE_URL required")
	}

	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer p.Close()

	switch cmd {
	case "grant":
		_, err = p.Exec(ctx, `INSERT INTO grants(subject,tool) VALUES($1,$2) ON CONFLICT DO NOTHING`, *sub, *tool)
	case "revoke":
		_, err = p.Exec(ctx, `DELETE FROM grants WHERE subject=$1 AND tool=$2`, *sub, *tool)
	case "list":
		var query string
		var queryArgs []any
		if *sub != "" && *tool != "" {
			query = `SELECT subject, tool FROM grants WHERE subject=$1 AND tool=$2 ORDER BY subject, tool`
			queryArgs = []any{*sub, *tool}
		} else if *sub != "" {
			query = `SELECT subject, tool FROM grants WHERE subject=$1 ORDER BY tool`
			queryArgs = []any{*sub}
		} else if *tool != "" {
			query = `SELECT subject, tool FROM grants WHERE tool=$1 ORDER BY subject`
			queryArgs = []any{*tool}
		} else {
			query = `SELECT subject, tool FROM grants ORDER BY subject, tool`
		}

		rows, qErr := p.Query(ctx, query, queryArgs...)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

		for rows.Next() {
			var s, t string
			if scanErr := rows.Scan(&s, &t); scanErr != nil {
				return scanErr
			}
			fmt.Fprintf(stdout, "%s\t%s\n", s, t)
		}
		return rows.Err()

	case "approve":
		b, e := os.ReadFile(*params)
		if e != nil {
			return e
		}
		// Operator must review the entire file, including arguments, before approving.
		var input struct {
			Name string `json:"name"`
		}
		if e = json.Unmarshal(b, &input); e != nil || input.Name != *tool {
			return fmt.Errorf("params tool does not match -tool")
		}
		digest, e := gateway.Digest(b)
		if e != nil {
			return e
		}
		token := make([]byte, 32)
		if _, e = rand.Read(token); e != nil {
			return e
		}
		raw := hex.EncodeToString(token)
		hash := sha256.Sum256([]byte(raw))
		expiresAt := time.Now().UTC().Add(*ttl)
		_, err = p.Exec(ctx, `INSERT INTO approvals(token_hash,subject,digest,expires_at) VALUES($1,$2,$3,$4)`, hex.EncodeToString(hash[:]), *sub, digest, expiresAt)
		if err == nil {
			fmt.Fprintln(stdout, raw)
		}
	}
	return err
}
