#!/usr/bin/env bash
# Install diri-agent-guardrails via curl:
#   curl -fsSL https://raw.githubusercontent.com/Team-Deepiri/diri-agent-guardrails/main/scripts/install.sh | bash
set -euo pipefail

REPO="Team-Deepiri/diri-agent-guardrails"
REPO_URL="https://github.com/${REPO}.git"
BRANCH="${DEEPIRI_AGENT_GUARDRAILS_BRANCH:-main}"
KEEP_DIR="${DEEPIRI_AGENT_GUARDRAILS_KEEP_DIR:-0}"
WITH_OPA="${DEEPIRI_AGENT_GUARDRAILS_OPA:-0}"

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Clone (when needed) and install diri-agent-guardrails (Poetry preferred).

Options:
  -h, --help     Show this help
  --dry-run      Print actions without installing
  --with-opa     Install optional [opa] extra (httpx)

Environment:
  DEEPIRI_AGENT_GUARDRAILS_SRC       Existing checkout
  DEEPIRI_AGENT_GUARDRAILS_BRANCH    Git branch (default: main)
  DEEPIRI_AGENT_GUARDRAILS_KEEP_DIR  Keep clone when set to 1
  DEEPIRI_AGENT_GUARDRAILS_OPA       Set to 1 to install [opa] extra

Requires: git, python3 (>=3.10), poetry (optional)
Verify:   python3 -c "import diri_agent_guardrails; print('ok')"
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --with-opa) WITH_OPA=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

for cmd in git python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "error: $cmd is required." >&2; exit 1; }
done

ROOT=""
CLEANUP=""

if [[ -n "${DEEPIRI_AGENT_GUARDRAILS_SRC:-}" && -f "${DEEPIRI_AGENT_GUARDRAILS_SRC}/pyproject.toml" ]]; then
  ROOT="${DEEPIRI_AGENT_GUARDRAILS_SRC}"
elif [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ "${BASH_SOURCE[0]}" != bash ]] && [[ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/pyproject.toml" ]]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  ROOT="$(mktemp -d)"
  [[ "$KEEP_DIR" != "1" ]] && CLEANUP="$ROOT"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "Would clone ${REPO_URL} to ${ROOT}"
    exit 0
  fi
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$ROOT"
fi

[[ "$DRY_RUN" -eq 1 ]] && { log "Would install from ${ROOT}"; exit 0; }

trap '[[ -n "$CLEANUP" ]] && rm -rf "$CLEANUP"' EXIT
cd "$ROOT"

EXTRAS=""
[[ "$WITH_OPA" == "1" ]] && EXTRAS="-E opa"

if command -v poetry >/dev/null 2>&1; then
  log "Installing with Poetry"
  if [[ -n "$EXTRAS" ]]; then
    poetry install --no-interaction --no-ansi --extras opa
  else
    poetry install --no-interaction --no-ansi
  fi
  PYTHON="poetry run python"
else
  warn "poetry not found; using pip editable install"
  VENV="${ROOT}/.venv"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -U pip wheel poetry-core -q
  if [[ -n "$EXTRAS" ]]; then
    "$VENV/bin/pip" install -e ".[opa]" -q
  else
    "$VENV/bin/pip" install -e . -q
  fi
  PYTHON="${VENV}/bin/python"
fi

"$PYTHON" -c "import diri_agent_guardrails; print('diri-agent-guardrails import ok')"
echo ""
echo "Verify: python3 -c \"import diri_agent_guardrails; print('ok')\""
