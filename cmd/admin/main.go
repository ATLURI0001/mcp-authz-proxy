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
	"github.com/ATLURI0001/mcp-authz-proxy/internal/gateway"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: admin grant|revoke|approve -subject UUID -tool NAME [-params file.json]")
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	sub := fs.String("subject", "", "exact issuer subject")
	tool := fs.String("tool", "", "tool name")
	params := fs.String("params", "", "complete tools/call params JSON file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *sub == "" || *tool == "" {
		return fmt.Errorf("subject and tool required")
	}
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	p, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer p.Close()
	switch cmd {
	case "grant":
		_, err = p.Exec(ctx, `INSERT INTO grants(subject,tool) VALUES($1,$2) ON CONFLICT DO NOTHING`, *sub, *tool)
	case "revoke":
		_, err = p.Exec(ctx, `DELETE FROM grants WHERE subject=$1 AND tool=$2`, *sub, *tool)
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
		_, err = p.Exec(ctx, `INSERT INTO approvals(token_hash,subject,digest,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, hex.EncodeToString(hash[:]), *sub, digest)
		if err == nil {
			fmt.Println(raw)
		}
	default:
		return fmt.Errorf("unknown command")
	}
	return err
}
