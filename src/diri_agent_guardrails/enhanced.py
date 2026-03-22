"""
Rule-based enhanced guardrails with optional PostgreSQL persistence.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from diri_agent_guardrails.protocols import AsyncPostgresClient

logger = logging.getLogger(__name__)


class GuardrailRule:
    """Individual guardrail rule definition."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        action: str = "block",
        severity: str = "medium",
        description: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.action = action
        self.severity = severity
        self.description = description

    def check(self, text: str) -> Optional[Dict[str, Any]]:
        match = self.pattern.search(text)
        if match:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "action": self.action,
                "severity": self.severity,
                "match": match.group(),
                "description": self.description,
            }
        return None


class EnhancedGuardrails:
    """
    Rule-based guardrails with optional DB-backed rules and violation logging.
    When ``postgres`` is ``None``, only in-memory default rules apply.
    """

    def __init__(
        self,
        postgres: Optional[AsyncPostgresClient] = None,
        schema: str = "cyrex",
    ) -> None:
        self._rules: Dict[str, GuardrailRule] = {}
        self._custom_validators: List[Callable[..., Any]] = []
        self.logger = logger
        self._postgres = postgres
        self._schema = schema

    async def initialize(self) -> None:
        if self._postgres is not None:
            await self._postgres.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
            await self._postgres.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._schema}.guardrail_rules (
                    rule_id VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    pattern TEXT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    description TEXT,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
                """
            )
            await self._postgres.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_guardrails_enabled
                    ON {self._schema}.guardrail_rules(enabled)
                """
            )
            await self._postgres.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._schema}.guardrail_violations (
                    violation_id VARCHAR(255) PRIMARY KEY,
                    rule_id VARCHAR(255) NOT NULL,
                    content TEXT,
                    action_taken VARCHAR(50),
                    severity VARCHAR(50),
                    timestamp TIMESTAMP NOT NULL
                )
                """
            )
            await self._postgres.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_violations_rule_id
                    ON {self._schema}.guardrail_violations(rule_id)
                """
            )
            await self._postgres.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_violations_timestamp
                    ON {self._schema}.guardrail_violations(timestamp)
                """
            )

        await self._load_default_rules()
        if self._postgres is not None:
            await self._load_rules_from_db()

        self.logger.info("Enhanced guardrails initialized")

    async def _load_default_rules(self) -> None:
        default_rules = [
            {
                "rule_id": "profanity_1",
                "name": "Profanity Filter",
                "pattern": r"\b(fuck|shit|damn|bitch|asshole)\b",
                "action": "block",
                "severity": "medium",
                "description": "Blocks profane language",
            },
            {
                "rule_id": "pii_1",
                "name": "PII Detection",
                "pattern": r"\b\d{3}-\d{2}-\d{4}|\b\d{16}\b",
                "action": "warn",
                "severity": "high",
                "description": "Detects potential PII (SSN, credit card) — email excluded",
            },
            {
                "rule_id": "toxicity_1",
                "name": "Toxicity Detection",
                "pattern": r"\b(kill|die|hate|stupid|idiot|moron)\b",
                "action": "warn",
                "severity": "medium",
                "description": "Detects potentially toxic language",
            },
        ]
        for rule_data in default_rules:
            rule = GuardrailRule(**rule_data)
            self._rules[rule.rule_id] = rule

    async def _load_rules_from_db(self) -> None:
        assert self._postgres is not None
        rows = await self._postgres.fetch(
            f"SELECT * FROM {self._schema}.guardrail_rules WHERE enabled = TRUE"
        )
        for row in rows:
            rule = GuardrailRule(
                rule_id=row["rule_id"],
                name=row["name"],
                pattern=row["pattern"],
                action=row["action"],
                severity=row["severity"],
                description=row["description"] or "",
            )
            self._rules[rule.rule_id] = rule

    async def add_rule(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        action: str = "block",
        severity: str = "medium",
        description: str = "",
    ) -> None:
        rule = GuardrailRule(rule_id, name, pattern, action, severity, description)
        self._rules[rule_id] = rule

        if self._postgres is not None:
            now = datetime.now(timezone.utc)
            await self._postgres.execute(
                f"""
                INSERT INTO {self._schema}.guardrail_rules
                    (rule_id, name, pattern, action, severity, description, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (rule_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    pattern = EXCLUDED.pattern,
                    action = EXCLUDED.action,
                    severity = EXCLUDED.severity,
                    description = EXCLUDED.description,
                    updated_at = EXCLUDED.updated_at
                """,
                rule_id,
                name,
                pattern,
                action,
                severity,
                description,
                now,
                now,
            )

        self.logger.info("Guardrail rule added: %s", rule_id)

    async def check(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        violations: List[Dict[str, Any]] = []
        action = "allow"
        modified_text = text

        for rule in self._rules.values():
            result = rule.check(text)
            if result:
                violations.append(result)
                if rule.action == "block" or rule.severity == "critical":
                    action = "block"
                elif action != "block" and (rule.action == "warn" or rule.severity == "high"):
                    action = "warn"
                elif action == "allow" and rule.action == "modify":
                    action = "modify"
                    modified_text = rule.pattern.sub("[REDACTED]", modified_text)

        for validator in self._custom_validators:
            try:
                if asyncio.iscoroutinefunction(validator):
                    result = await validator(text, context or {})
                else:
                    result = validator(text, context or {})

                if result and not result.get("safe", True):
                    violations.append(
                        {
                            "rule_id": "custom",
                            "name": "Custom Validator",
                            "action": result.get("action", "warn"),
                            "severity": result.get("severity", "medium"),
                            "description": result.get("description", "Custom validation failed"),
                        }
                    )
                    if result.get("action") == "block":
                        action = "block"
            except Exception as e:
                self.logger.warning("Custom validator error: %s", e)

        if violations:
            await self._log_violations(violations, text, action)

        return {
            "safe": len(violations) == 0 or action != "block",
            "violations": violations,
            "action": action,
            "modified_text": modified_text if action == "modify" else text,
        }

    async def _log_violations(
        self,
        violations: List[Dict[str, Any]],
        content: str,
        action_taken: str,
    ) -> None:
        if self._postgres is None:
            return

        for violation in violations:
            violation_id = f"{violation['rule_id']}_{uuid.uuid4().hex[:12]}"
            await self._postgres.execute(
                f"""
                INSERT INTO {self._schema}.guardrail_violations
                    (violation_id, rule_id, content, action_taken, severity, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                violation_id,
                violation["rule_id"],
                content[:1000],
                action_taken,
                violation["severity"],
                datetime.now(timezone.utc),
            )

    def add_validator(self, validator: Callable[..., Any]) -> None:
        self._custom_validators.append(validator)
        self.logger.debug("Custom validator added")


_enhanced_guardrails: Optional[EnhancedGuardrails] = None


async def get_enhanced_guardrails(
    postgres: Optional[AsyncPostgresClient] = None,
    schema: str = "cyrex",
) -> EnhancedGuardrails:
    """
    Singleton accessor. Pass ``postgres`` on first call when using DB-backed rules.

    Example (Cyrex-style)::

        pg = await get_postgres_manager()
        g = await get_enhanced_guardrails(postgres=pg)
    """
    global _enhanced_guardrails
    if _enhanced_guardrails is None:
        _enhanced_guardrails = EnhancedGuardrails(postgres=postgres, schema=schema)
        await _enhanced_guardrails.initialize()
    return _enhanced_guardrails


def reset_enhanced_guardrails() -> None:
    """Clear singleton (tests / process reload)."""
    global _enhanced_guardrails
    _enhanced_guardrails = None
