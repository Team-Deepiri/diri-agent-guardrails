# diri-agent-guardrails

Python library for **AI agent guardrails**: input/output sanitization, PII detection (patterns, optional redaction paths), prompt-injection checks, policy-driven safety, optional PostgreSQL-backed rules, and an optional [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) REST helper.

Most agent stacks reimplement the same boring checks. This package standardizes them so you can ship faster and stay consistent across services.

## Install

```bash
pip install diri-agent-guardrails
```

Development install:

```bash
git clone https://github.com/Team-Deepiri/diri-agent-guardrails.git
cd diri-agent-guardrails
poetry install --with dev
```

Optional OPA client (`httpx`):

```bash
pip install diri-agent-guardrails[opa]
```

## Quick start

**Classic (sync) — prompt, PII heuristics, output checks**

```python
from diri_agent_guardrails import SafetyGuardrails

g = SafetyGuardrails()
result = g.check_prompt(user_text)
if g.should_block(result):
    ...
```

**Advanced (async) — policies, tool safety, rate limits**

```python
from diri_agent_guardrails import get_advanced_guardrails

guardrails = await get_advanced_guardrails()
inp = await guardrails.check_input(user_text)
out = await guardrails.check_output(model_text)
```

**Enhanced — configurable rules, optional Postgres**

```python
from diri_agent_guardrails import get_enhanced_guardrails

# In-memory defaults only:
g = await get_enhanced_guardrails()

# With your async Postgres client (same shape as Cyrex PostgreSQLManager):
g = await get_enhanced_guardrails(postgres=await get_postgres_manager(), schema="cyrex")
summary = await g.check(text)
```

**OPA (optional)**

```python
from diri_agent_guardrails.opa import evaluate_opa

result = await evaluate_opa(
    input_data={"user": {"role": "guest"}, "text": user_text},
    policy_path="agent/guardrails/allow",
)
```

## Modules

| Module | Role |
|--------|------|
| `safety` | `SafetyGuardrails` — lightweight sync checks |
| `advanced` | `AdvancedGuardrails` — policies, categories, async API |
| `enhanced` | `EnhancedGuardrails` — rules + optional DB persistence |
| `opa` | `evaluate_opa` — call OPA `/v1/data/...` (needs `[opa]`) |

## Relationship to Cyrex

This code was extracted from the **Deepiri Cyrex** codebase (`guardrails.py`, `advanced_guardrails.py`, `enhanced_guardrails.py`). Cyrex can depend on this package and thin wrappers can pass app-specific loggers or Postgres clients.

## License

MIT — see [LICENSE](LICENSE).
