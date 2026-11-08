// demo-server is a stateless JSON-only MCP fixture. Never expose it publicly.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	tokens := map[string]string{"alice": os.Getenv("UPSTREAM_ALICE_TOKEN"), "bob": os.Getenv("UPSTREAM_BOB_TOKEN")}
	for _, v := range tokens {
		if len(v) < 16 {
			log.Fatal("demo tokens must be configured")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		user := ""
		for name, token := range tokens {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1 {
				user = name
			}
		}
		if user == "" {
			w.WriteHeader(401)
			return
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1048576)).Decode(&req) != nil {
			w.WriteHeader(400)
			return
		}
		var result any
		switch req.Method {
		case "tools/list":
			result = map[string]any{"tools": []any{
				map[string]any{"name": "echo", "description": "Echo a message without side effects", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}, "required": []string{"message"}, "additionalProperties": false}},
				map[string]any{"name": "whoami", "description": "Identify the downstream credential owner", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
				map[string]any{"name": "restart_demo", "description": "Simulate a restart; no real infrastructure is changed", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
			}}
		case "tools/call":
			text := ""
			bad := false
			switch req.Params.Name {
			case "echo":
				var ok bool
				text, ok = req.Params.Arguments["message"].(string)
				if !ok || len(req.Params.Arguments) != 1 {
					bad = true
					text = "expected one string argument: message"
				}
			case "whoami":
				text = user
				if len(req.Params.Arguments) != 0 {
					bad = true
					text = "no arguments expected"
				}
			case "restart_demo":
				text = "simulated restart approved for " + user
				if len(req.Params.Arguments) != 0 {
					bad = true
					text = "no arguments expected"
				}
			default:
				bad = true
				text = "unknown tool"
			}
			result = map[string]any{"content": []any{map[string]string{"type": "text", "text": text}}, "isError": bad}
		default:
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})
	s := &http.Server{Addr: ":8081", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	log.Fatal(s.ListenAndServe())
}
