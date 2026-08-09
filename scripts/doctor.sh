#!/bin/sh
# Is the toolchain this repo's Makefile needs actually present and runnable?
# Modeled on the family's doctor scripts: RUN each candidate, don't just
# locate it — on Windows `python3` resolves to a Store alias stub that exists
# on PATH and exits 49 when executed.
set -u

fail=0
ok()  { printf '  ok    %-10s %s\n' "$1" "$2"; }
bad() { printf '  bad   %-10s %s\n' "$1" "$2"; fail=1; }

if go version >/dev/null 2>&1; then ok go "$(go version | cut -d' ' -f3)"; else bad go "not runnable"; fi
if docker info >/dev/null 2>&1; then ok docker "daemon reachable"; else bad docker "daemon not reachable"; fi
if docker compose version >/dev/null 2>&1; then ok compose "$(docker compose version --short 2>/dev/null)"; else bad compose "docker compose v2 plugin missing"; fi
if pnpm --version >/dev/null 2>&1; then ok pnpm "$(pnpm --version)"; else bad pnpm "not runnable (JS witness + docs site)"; fi
if uv --version >/dev/null 2>&1; then ok uv "$(uv --version | cut -d' ' -f2)"; else bad uv "not runnable (python witness)"; fi
if dotnet --version >/dev/null 2>&1; then ok dotnet "$(dotnet --version)"; else bad dotnet "not runnable (.NET witness)"; fi

exit $fail
