.PHONY: build docs test test-coverage test-differential test-sdks setup-sdks verify

build:
	go build ./...

test:
	go test -race ./...

test-coverage:
	go test -coverpkg=./... -coverprofile=cover.out ./...
	go tool cover -func=cover.out | awk '/^total:/ { print; if ($$3 != "100.0%") exit 1 }'

test-differential:
	go test -count=1 -v ./e2e/differential

setup-sdks:
	npm install --prefix e2e/javascript
	python3 -m venv e2e/python/.venv
	e2e/python/.venv/bin/python -m pip install -r e2e/python/requirements.txt
	dotnet restore e2e/dotnet/Witness.csproj

test-sdks:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v ./e2e/sdk

docs:
	mkdocs build --strict

verify: build test test-coverage
	go vet ./...
