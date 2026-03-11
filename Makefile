.PHONY: build test test-coverage lint bench clean

build:
	CGO_ENABLED=0 go build -o curb .

test:
	go test ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	@test -z "$$(go fix -diff ./... 2>&1)" || { go fix -diff ./...; echo "go fix: run 'go fix ./...' to apply fixes"; exit 1; }
	golangci-lint run ./...

bench:
	go test -bench=. -benchtime=5s -count=3 ./bench/

clean:
	rm -f curb coverage.out
