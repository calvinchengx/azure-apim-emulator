# Thin wrappers over the docker compose pair (entra + apim). The compose file
# is the source of truth; these exist so the everyday cycle is one word each,
# the same way the whole emulator family is driven.
#
# Windows: recipes run under sh.exe (Git for Windows). GNU Make falls back to
# cmd.exe when it cannot find a shell, and cmd cannot run a line of this.
ifeq ($(OS),Windows_NT)
  SHELL := sh.exe
  .SHELLFLAGS := -c
endif

COMPOSE = docker compose -f compose.yaml

.PHONY: build docs test test-coverage test-differential test-sdks setup-sdks \
        setup-graphql test-graphql setup-grpc test-grpc setup-soap test-soap setup-credential test-credential setup-openai test-openai setup-mcp test-mcp verify \
        check-inventory up down clean status doctor ps logs

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
	# A venv DIRECTORY, not an interpreter path: uv resolves bin/python vs
	# Scripts/python.exe itself, so this line works on Windows too.
	uv pip install --python e2e/python/.venv -r e2e/python/requirements.txt
	dotnet restore e2e/dotnet/Witness.csproj

test-sdks:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v ./e2e/sdk

# The GraphQL witness needs only Go and pnpm, so it runs as its own job rather
# than behind setup-sdks' dotnet and python installs. Keeping it separate also
# means a break in one of those suites cannot hide a GraphQL regression.
setup-graphql:
	pnpm install --frozen-lockfile

test-graphql:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/graphql' ./e2e/sdk

# Same reasoning as the GraphQL witness: Go and pnpm only, and its own job so a
# break in the dotnet or python suites cannot hide a gRPC regression.
setup-grpc:
	pnpm install --frozen-lockfile

test-grpc:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/grpc' ./e2e/sdk

setup-soap:
	pnpm install --frozen-lockfile

test-soap:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/soap' ./e2e/sdk

setup-credential:
	pnpm install --frozen-lockfile

test-credential:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/credential' ./e2e/sdk

setup-openai:
	pnpm install --frozen-lockfile

test-openai:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/openai' ./e2e/sdk

setup-mcp:
	pnpm install --frozen-lockfile

test-mcp:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/mcp' ./e2e/sdk

docs:
	pnpm --filter azure-apim-emulator-docs build

check-inventory:
	python3 scripts/check_policy_inventory.py --strict

verify: build test test-coverage
	go vet ./...

up: ## Start the pair (entra pinned + apim built from source)
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v

status: ## Is the pair actually usable? (non-zero exit if not)
	@sh scripts/status.sh

doctor: ## Check the toolchain this Makefile needs
	@sh scripts/doctor.sh

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail 100
