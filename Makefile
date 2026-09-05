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

.PHONY: build docs-build docs-serve setup-websocket test-websocket setup-keyvault test-keyvault clean-keyvault test test-coverage test-differential test-sdks setup-sdks \
        test-operation-inventory setup-graphql test-graphql setup-grpc test-grpc setup-soap test-soap setup-credential test-credential setup-openai test-openai setup-mcp test-mcp setup-openid test-openid verify \
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

# The ARM-document witness: Microsoft's packaged JavaScript client round-tripping
# every ARM resource family. Go and pnpm only, and its own job so a break in the
# management-plane documents cannot hide inside the broader SDK suite.
setup-arm-documents:
	pnpm install --frozen-lockfile

test-arm-documents:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/arm-documents' ./e2e/sdk

# The GraphQL witness needs only Go and pnpm, so it runs as its own job rather
# than behind setup-sdks' dotnet and python installs. Keeping it separate also
# means a break in one of those suites cannot hide a GraphQL regression.
# The WebSocket/SSE witness needs only Go and pnpm. Its own job for the usual
# reason: a streaming regression must not hide inside a suite that also covers
# GraphQL or gRPC.
# The Key Vault witness needs DOCKER, unlike every other witness here, because
# the vault's 401 challenge names container hostnames and both apim and the
# witness have to resolve them. See e2e/keyvault/compose.yaml.
setup-keyvault:
	pnpm install --frozen-lockfile
	docker compose -f e2e/keyvault/compose.yaml up -d --build --wait

test-keyvault:
	docker compose -f e2e/keyvault/compose.yaml --profile witness run --rm witness

clean-keyvault:
	docker compose -f e2e/keyvault/compose.yaml --profile witness down -v

setup-websocket:
	pnpm install --frozen-lockfile

test-websocket:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/websocket' ./e2e/sdk

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

setup-openid:
	pnpm install --frozen-lockfile

test-openid:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/openid' ./e2e/sdk

setup-mcp:
	pnpm install --frozen-lockfile

test-mcp:
	APIM_RUN_EXTERNAL_SDK_TESTS=1 go test -count=1 -v -run 'TestOfficialManagementSDKs/mcp' ./e2e/sdk

# ---------------------------------------------------------------------------
# The documentation site.
#
# This target used to be `docs`, and it ran the Starlight build alone. That
# leaves website/dist, which is NOT the published site: the published site is
# the landing page at the root with the docs beneath it, plus the redirect
# stubs and llms.txt. Anyone who ran `make docs` and looked at the result was
# looking at something GitHub Pages never serves.
#
# Renamed as well as widened, because there is a docs/ DIRECTORY here: a target
# sharing its name is satisfied by the directory existing, so `make docs`
# without .PHONY prints "nothing to be done" and exits 0. A name that cannot
# collide fixes that whether or not anyone remembers .PHONY.
#
# `pnpm --filter $(DOCS_PKG) dev` is the fast inner loop for PROSE, and it is
# not this. It is based at the docs subpath and knows nothing about the tree
# around it, so under it the landing page does not exist, the redirect stubs do
# not exist, and the manifests the landing page fetches do not exist. Use it to
# write a page; use `make docs-serve` before believing the site works.
#
# CI runs `make docs-build` and publishes exactly what it leaves in ./_site, so
# the thing previewed here is the thing that deploys.
DOCS_PKG  ?= azure-apim-emulator-docs
DOCS_PORT ?= 8099
# The interpreter CI uses, pinned. These scripts are stdlib-only, hence
# --no-project: no environment to resolve, and a local 3.9 cannot pass
# something 3.12 would reject.
UVPY ?= uv run --no-project --python 3.12 python

docs-build:
	@command -v uv >/dev/null 2>&1 || { echo "uv is not on PATH: https://docs.astral.sh/uv/" >&2; exit 1; }
	pnpm install --frozen-lockfile
	@# Both of these READ the docs, so a prose-only change must run them. See
	@# the long note in .github/workflows/docs-site.yml for why they live in
	@# two workflows rather than one.
	$(UVPY) scripts/check_witnesses.py --strict
	$(UVPY) scripts/check_docs_links.py --strict
	pnpm --filter $(DOCS_PKG) build
	$(UVPY) scripts/assemble_site.py --self-test
	$(UVPY) scripts/assemble_site.py --out _site
	@# llms.txt at the SITE root, which is where the convention says to look.
	@# sync-docs writes it into website/public/, which Astro copies to the root
	@# of the BUILT site, and this site's base is /azure-apim-emulator/docs/, so
	@# that lands one level too deep. Copied up rather than moved:
	@# /docs/llms.txt describes the docs and is correct where it is.
	cp website/dist/llms.txt _site/llms.txt
	$(UVPY) scripts/build_landing_data.py --out _site --landing site/index.html

docs-serve: docs-build
	$(UVPY) scripts/assemble_site.py --serve --site _site --port $(DOCS_PORT)

test-operation-inventory:
	APIM_RUN_OPERATION_INVENTORY=1 go test -count=1 -timeout 20m ./e2e/inventory/...

check-inventory: test-scripts
	python3 scripts/check_docs_links.py --strict
	python3 scripts/check_policy_inventory.py --strict
	python3 scripts/check_operation_inventory.py --strict
	python3 scripts/derive_expression_surface.py --check
	python3 scripts/derive_limit_attributes.py --check
	python3 scripts/derive_policy_sections.py --check

# The derivations decide what the compiler rejects, so the reading they do is
# tested rather than only re-run. `--check` alone proves a record matches what
# the script derives today; it says nothing about whether the script still reads
# the source correctly, which is where the section table was wrong before.
test-scripts:
	python3 -m unittest discover -s scripts -p 'test_*.py'

# check-format fails on anything gofmt would rewrite. go vet does not look at
# formatting, so without this an alignment change rides into main unnoticed:
# adding one longer field to a struct makes gofmt want to realign every field
# under it, and that is exactly how internal/policy/policy.go and
# internal/policy/lasterror.go came to be unformatted on main.
check-format:
	@unformatted=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt would rewrite:"; echo "$$unformatted"; \
		echo "run: gofmt -w $$unformatted"; \
		exit 1; \
	fi
	@echo "gofmt: clean"

verify: build test test-coverage check-format
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
