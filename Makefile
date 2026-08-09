.PHONY: build docs test test-coverage test-differential test-sdks setup-sdks verify

build:
	go build ./...

test:
	go test -race ./...

test-coverage:
	go test -coverpkg=./... -coverprofile=cover.raw ./...
	awk 'NR == 1 { print; next } { key = $$1 FS $$2; if (!(key in max) || $$3 > max[key]) { max[key] = $$3; line[key] = $$0 } } END { for (key in line) print line[key] }' cover.raw > cover.out
	go tool cover -func=cover.out | awk '/^total:/ { print; if ($$3 != "100.0%") exit 1 }'

test-differential:
	go test -count=1 -v ./e2e/differential

setup-sdks:
	pnpm install --frozen-lockfile
	uv venv e2e/python/.venv
	uv pip install --python e2e/python/.venv/bin/python -r e2e/python/requirements.txt
	dotnet restore e2e/dotnet/Witness.csproj

test-sdks:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v ./e2e/sdk

docs:
	pnpm --filter azure-apim-emulator-docs build

verify: build test test-coverage
	go vet ./...
