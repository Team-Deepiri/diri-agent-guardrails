"""
Advanced guardrails: policies, categories, async checks, rate limits, tool safety.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardrailAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    MODIFY = "modify"
    BLOCK = "block"
    ESCALATE = "escalate"
    LOG = "log"


class GuardrailCategory(str, Enum):
    CONTENT_SAFETY = "content_safety"
    PROMPT_INJECTION = "prompt_injection"
    DATA_PRIVACY = "data_privacy"
    OUTPUT_VALIDATION = "output_validation"
    RATE_LIMITING = "rate_limiting"
    TOOL_SAFETY = "tool_safety"
    CONTEXT_BOUNDARY = "context_boundary"
    ETHICAL = "ethical"


@dataclass
class GuardrailResult:
    passed: bool
    risk_level: RiskLevel = RiskLevel.SAFE
    action: GuardrailAction = GuardrailAction.ALLOW
    category: GuardrailCategory = GuardrailCategory.CONTENT_SAFETY
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    modified_content: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "risk_level": self.risk_level.value,
            "action": self.action.value,
            "category": self.category.value,
            "message": self.message,
            "details": self.details,
            "modified_content": self.modified_content,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class GuardrailPolicy:
    name: str
    category: GuardrailCategory
    enabled: bool = True
    risk_threshold: RiskLevel = RiskLevel.MEDIUM
    action_on_violation: GuardrailAction = GuardrailAction.BLOCK
    patterns: List[str] = field(default_factory=list)
    allow_list: List[str] = field(default_factory=list)
    block_list: List[str] = field(default_factory=list)
    custom_check: Optional[Callable[..., Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdvancedGuardrails:
    """
    Policy-driven guardrails: content safety, prompt injection, PII/data privacy,
    output validation, rate limiting, tool safety, and context boundaries.
    """

    def __init__(self) -> None:
        self.policies: Dict[str, GuardrailPolicy] = {}
        self._compiled_patterns: Dict[str, List[re.Pattern[str]]] = {}
        self._rate_limits: Dict[str, Dict[str, Any]] = {}
        self._blocked_tools: Set[str] = set()
        self.logger = logger
        self._initialize_default_policies()

    def _initialize_default_policies(self) -> None:
        self.add_policy(
            GuardrailPolicy(
                name="prompt_injection",
                category=GuardrailCategory.PROMPT_INJECTION,
                risk_threshold=RiskLevel.HIGH,
                action_on_violation=GuardrailAction.BLOCK,
                patterns=[
                    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)",
                    r"disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?)",
                    r"forget\s+(?:everything|all)\s+(?:above|before)",
                    r"system\s*:\s*",
                    r"<\|?(?:system|assistant|user)\|?>",
                    r"new\s+(?:system\s+)?instructions?\s*:",
                    r"jailbreak",
                    r"DAN\s+mode",
                    r"developer\s+mode",
                    r"bypass\s+(?:safety|restrictions?|filters?)",
                    r"pretend\s+(?:you\s+are|to\s+be)",
                    r"roleplay\s+as\s+(?:an?\s+)?(?:evil|malicious)",
                ],
            )
        )

        self.add_policy(
            GuardrailPolicy(
                name="harmful_content",
                category=GuardrailCategory.CONTENT_SAFETY,
                risk_threshold=RiskLevel.HIGH,
                action_on_violation=GuardrailAction.BLOCK,
                patterns=[
                    r"\b(?:how\s+to\s+)?(?:make|create|build)\s+(?:a\s+)?(?:bomb|weapon|explosive)",
                    r"\b(?:how\s+to\s+)?(?:harm|hurt|kill|attack)\s+(?:someone|people)",
                    r"\b(?:synthesize|produce)\s+(?:drugs?|narcotics?|poison)",
                ],
            )
        )

        self.add_policy(
            GuardrailPolicy(
                name="pii_detection",
                category=GuardrailCategory.DATA_PRIVACY,
                risk_threshold=RiskLevel.MEDIUM,
                action_on_violation=GuardrailAction.WARN,
                patterns=[
                    r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
                    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                    r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                    r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
                    r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S+",
                ],
            )
        )

        self.add_policy(
            GuardrailPolicy(
                name="output_limits",
                category=GuardrailCategory.OUTPUT_VALIDATION,
                risk_threshold=RiskLevel.LOW,
                action_on_violation=GuardrailAction.MODIFY,
                metadata={"max_length": 10000, "max_tokens": 4000},
            )
        )

        self.add_policy(
            GuardrailPolicy(
                name="tool_safety",
                category=GuardrailCategory.TOOL_SAFETY,
                risk_threshold=RiskLevel.HIGH,
                action_on_violation=GuardrailAction.BLOCK,
                block_list=[
                    "execute_shell",
                    "run_command",
                    "delete_database",
                    "drop_table",
                    "rm_rf",
                ],
            )
        )

        self.add_policy(
            GuardrailPolicy(
                name="ethical_guidelines",
                category=GuardrailCategory.ETHICAL,
                risk_threshold=RiskLevel.MEDIUM,
                action_on_violation=GuardrailAction.WARN,
                patterns=[
                    r"\b(?:discriminate|hate|racist|sexist)\b",
                    r"\b(?:illegal|fraudulent|scam)\s+(?:activity|scheme)",
                ],
            )
        )

    def add_policy(self, policy: GuardrailPolicy) -> None:
        self.policies[policy.name] = policy
        if policy.patterns:
            self._compiled_patterns[policy.name] = [
                re.compile(p, re.IGNORECASE) for p in policy.patterns
            ]
        self.logger.info("Added guardrail policy: %s", policy.name)

    def reload_policies(self) -> None:
        self.policies.clear()
        self._compiled_patterns.clear()
        self._initialize_default_policies()
        self.logger.info("Guardrail policies reloaded")

    def remove_policy(self, policy_name: str) -> None:
        self.policies.pop(policy_name, None)
        self._compiled_patterns.pop(policy_name, None)

    def enable_policy(self, policy_name: str, enabled: bool = True) -> None:
        if policy_name in self.policies:
            self.policies[policy_name].enabled = enabled

    async def check_input(
        self,
        input_text: str,
        context: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> GuardrailResult:
        del context, user_id  # reserved for future policy hooks
        results: List[GuardrailResult] = []

        for policy_name, policy in self.policies.items():
            if not policy.enabled:
                continue
            if policy.category in (
                GuardrailCategory.PROMPT_INJECTION,
                GuardrailCategory.CONTENT_SAFETY,
                GuardrailCategory.DATA_PRIVACY,
                GuardrailCategory.ETHICAL,
            ):
                result = await self._check_patterns(input_text, policy)
                if not result.passed:
                    results.append(result)

        if results:
            risk_order = [
                RiskLevel.CRITICAL,
                RiskLevel.HIGH,
                RiskLevel.MEDIUM,
                RiskLevel.LOW,
            ]
            results.sort(
                key=lambda r: risk_order.index(r.risk_level) if r.risk_level in risk_order else 99
            )
            return results[0]

        return GuardrailResult(
            passed=True,
            risk_level=RiskLevel.SAFE,
            action=GuardrailAction.ALLOW,
            message="Input passed all guardrail checks",
        )

    async def check_output(
        self,
        output_text: str,
        expected_format: Optional[str] = None,
        max_length: Optional[int] = None,
    ) -> GuardrailResult:
        results: List[GuardrailResult] = []

        output_policy = self.policies.get("output_limits")
        if output_policy and output_policy.enabled:
            max_len = max_length or output_policy.metadata.get("max_length", 10000)
            if len(output_text) > max_len:
                results.append(
                    GuardrailResult(
                        passed=False,
                        risk_level=RiskLevel.LOW,
                        action=GuardrailAction.MODIFY,
                        category=GuardrailCategory.OUTPUT_VALIDATION,
                        message=f"Output exceeds max length ({len(output_text)} > {max_len})",
                        modified_content=output_text[:max_len] + "... [truncated]",
                    )
                )

        pii_policy = self.policies.get("pii_detection")
        if pii_policy and pii_policy.enabled:
            result = await self._check_patterns(output_text, pii_policy)
            if not result.passed:
                result.message = f"Output contains sensitive data: {result.message}"
                results.append(result)

        if expected_format == "json":
            try:
                json.loads(output_text)
            except json.JSONDecodeError as e:
                results.append(
                    GuardrailResult(
                        passed=False,
                        risk_level=RiskLevel.LOW,
                        action=GuardrailAction.WARN,
                        category=GuardrailCategory.OUTPUT_VALIDATION,
                        message=f"Invalid JSON format: {str(e)}",
                    )
                )

        for _policy_name, policy in self.policies.items():
            if not policy.enabled:
                continue
            if policy.category == GuardrailCategory.CONTENT_SAFETY:
                result = await self._check_patterns(output_text, policy)
                if not result.passed:
                    result.message = f"Output contains harmful content: {result.message}"
                    results.append(result)

        if results:
            order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
            results.sort(
                key=lambda r: order.index(r.risk_level) if r.risk_level in order else 99
            )
            return results[0]

        return GuardrailResult(
            passed=True,
            risk_level=RiskLevel.SAFE,
            action=GuardrailAction.ALLOW,
            message="Output passed all guardrail checks",
        )

    async def check_tool_call(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> GuardrailResult:
        del agent_id
        tool_policy = self.policies.get("tool_safety")
        if not tool_policy or not tool_policy.enabled:
            return GuardrailResult(passed=True, action=GuardrailAction.ALLOW)

        if tool_name in tool_policy.block_list or tool_name in self._blocked_tools:
            return GuardrailResult(
                passed=False,
                risk_level=RiskLevel.HIGH,
                action=GuardrailAction.BLOCK,
                category=GuardrailCategory.TOOL_SAFETY,
                message=f"Tool '{tool_name}' is blocked by policy",
            )

        params_str = json.dumps(parameters)
        dangerous_patterns = [
            r";\s*(?:rm|del|drop|delete)",
            r"--\s*",
            r"'\s*(?:OR|AND)\s*'",
            r"<script",
            r"javascript:",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, params_str, re.IGNORECASE):
                return GuardrailResult(
                    passed=False,
                    risk_level=RiskLevel.HIGH,
                    action=GuardrailAction.BLOCK,
                    category=GuardrailCategory.TOOL_SAFETY,
                    message="Dangerous pattern detected in tool parameters",
                    details={"pattern": pattern},
                )

        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            message="Tool call passed safety checks",
        )

    async def check_rate_limit(
        self,
        user_id: str,
        action: str = "default",
        limit: int = 100,
        window_seconds: int = 60,
    ) -> GuardrailResult:
        key = f"{user_id}:{action}"
        now = datetime.now(timezone.utc)

        if key not in self._rate_limits:
            self._rate_limits[key] = {"count": 0, "window_start": now}

        rate_info = self._rate_limits[key]
        if (now - rate_info["window_start"]).total_seconds() > window_seconds:
            rate_info["count"] = 0
            rate_info["window_start"] = now

        rate_info["count"] += 1

        if rate_info["count"] > limit:
            return GuardrailResult(
                passed=False,
                risk_level=RiskLevel.MEDIUM,
                action=GuardrailAction.BLOCK,
                category=GuardrailCategory.RATE_LIMITING,
                message=f"Rate limit exceeded: {rate_info['count']}/{limit} in {window_seconds}s",
                details={
                    "current_count": rate_info["count"],
                    "limit": limit,
                    "window_seconds": window_seconds,
                },
            )

        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            details={"remaining": limit - rate_info["count"]},
        )

    async def check_context_boundary(
        self,
        content: str,
        allowed_topics: Optional[List[str]] = None,
        blocked_topics: Optional[List[str]] = None,
    ) -> GuardrailResult:
        del allowed_topics
        content_lower = content.lower()
        if blocked_topics:
            for topic in blocked_topics:
                if topic.lower() in content_lower:
                    return GuardrailResult(
                        passed=False,
                        risk_level=RiskLevel.MEDIUM,
                        action=GuardrailAction.WARN,
                        category=GuardrailCategory.CONTEXT_BOUNDARY,
                        message=f"Content touches blocked topic: {topic}",
                    )

        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            message="Content within context boundaries",
        )

    async def _check_patterns(self, text: str, policy: GuardrailPolicy) -> GuardrailResult:
        compiled = self._compiled_patterns.get(policy.name, [])
        for pattern in compiled:
            match = pattern.search(text)
            if match:
                matched_text = match.group()
                if "@" in matched_text and "." in matched_text:
                    self.logger.warning(
                        "Skipping email-like match in policy '%s': '%s' (pattern: '%s')",
                        policy.name,
                        matched_text,
                        pattern.pattern,
                    )
                    continue

                return GuardrailResult(
                    passed=False,
                    risk_level=policy.risk_threshold,
                    action=policy.action_on_violation,
                    category=policy.category,
                    message=f"Pattern match: {matched_text}",
                    details={
                        "policy": policy.name,
                        "match": matched_text,
                        "position": match.start(),
                    },
                )

        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            category=policy.category,
        )

    async def check(
        self,
        input_text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = await self.check_input(input_text, context)
        return {
            "safe": result.passed,
            "action": result.action.value,
            "risk_level": result.risk_level.value,
            "message": result.message,
            "details": result.details,
        }

    def block_tool(self, tool_name: str) -> None:
        self._blocked_tools.add(tool_name)

    def unblock_tool(self, tool_name: str) -> None:
        self._blocked_tools.discard(tool_name)

    def get_blocked_tools(self) -> List[str]:
        return list(self._blocked_tools)


_guardrails: Optional[AdvancedGuardrails] = None


async def get_advanced_guardrails(force_reload: bool = False) -> AdvancedGuardrails:
    global _guardrails
    if _guardrails is None or force_reload:
        _guardrails = AdvancedGuardrails()
    return _guardrails


def reload_guardrails() -> None:
    global _guardrails
    _guardrails = None
