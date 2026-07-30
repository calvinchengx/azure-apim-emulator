.PHONY: build test test-coverage verify

build:
	go build ./...

test:
	go test -race ./...

test-coverage:
	go test -coverpkg=./... -coverprofile=cover.out ./...
	go tool cover -func=cover.out | awk '/^total:/ { print; if ($$3 != "100.0%") exit 1 }'

verify: build test test-coverage
	go vet ./...
