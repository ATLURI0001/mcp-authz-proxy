.PHONY: test build demo down

test:
	go vet ./...
	go test -race -count=1 -coverprofile=coverage.out ./...

build:
	go build -o bin/gateway ./cmd/gateway
	go build -o bin/demo-server ./cmd/demo-server
	go build -o bin/admin ./cmd/admin

demo:
	python3 scripts/setup-demo.py
	docker compose up --build -d
	python3 scripts/smoke.py

down:
	docker compose down
