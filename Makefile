.PHONY: build test test-coverage test-distro lint govulncheck bench clean

build:
	CGO_ENABLED=0 go build -o curb .

test:
	go test ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-distro:
	./test/distro-smoke.sh

lint:
	@test -z "$$(go fix -diff ./...)" || { go fix -diff ./...; echo "go fix: run 'go fix ./...' to apply fixes"; exit 1; }
	golangci-lint run ./...

govulncheck:
	go tool govulncheck ./...

bench:
	go test -bench=. -benchtime=5s -count=3 ./bench/

clean:
	rm -f curb coverage.out
