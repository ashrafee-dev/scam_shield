"""Scam detection scoring engine.

The engine applies all registered DetectionRules to normalized input text,
aggregates weighted scores, and produces a structured AnalysisResult.

Architecture note:
  The engine is stateless — it receives text and returns a result. It has
  no knowledge of sessions, HTTP, or persistence. This makes it trivially
  testable and reusable across all analysis channels.
"""

from __future__ import annotations

import re

from app.domain.entities import (
    AnalysisResult,
    MatchedSignal,
    RiskLevel,
    SenderRisk,
)
from app.services.analysis.models import DetectionRule, RuleMatch, ScoringContext
from app.services.analysis.normalizers import extract_urls, normalize_for_matching
from app.services.analysis.rules import DETECTION_RULES

# ------------------------------------------------------------------ Constants

RISK_LEVEL_THRESHOLDS: list[tuple[int, RiskLevel]] = [
    (70, RiskLevel.HIGH),
    (30, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
]

_CATEGORY_ACTIONS: dict[str, str] = {
    "OTP theft": "Do not share verification codes or one-time passwords with anyone.",
    "phishing": "Do not click links from this sender. Go directly to the official website.",
    "bank impersonation": "Hang up and contact your bank directly using the number on the back of your card.",
    "tech support scam": "Hang up. Do not allow remote access to your device.",
    "IRS/government impersonation": "Hang up. The IRS and government agencies do not call demanding immediate payment.",
    "payment fraud": "Do not send payment by gift card, cryptocurrency, or wire transfer.",
    "account takeover attempt": "Do not provide credentials. Log in directly via the official app or website.",
    "legal threat": "Legitimate legal actions arrive via certified mail. Hang up or ignore this communication.",
    "manipulation": "This communication shows psychological manipulation tactics. Do not comply.",
    "lottery/prize scam": "You have not won a prize. Do not send money or personal information to claim a 'prize'.",
    "urgency": "Take time to verify through an official channel before acting.",
}

_DEFAULT_ACTION = "Verify the legitimacy of this communication through official channels before taking any action."


# ------------------------------------------------------------------ Engine


class DetectionEngine:
    """Applies all detection rules to input text and returns a scored result.

    Usage:
        engine = DetectionEngine()
        result = engine.analyze("Your account will be suspended. Read me the OTP.")
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self._rules = rules if rules is not None else DETECTION_RULES

    def analyze(
        self,
        text: str,
        *,
        transcript: str | None = None,
        sender_risk: SenderRisk | None = None,
    ) -> AnalysisResult:
        """Analyze text and return a fully populated AnalysisResult.

        Args:
            text: The raw input text to analyze.
            transcript: Optional transcript string (for audio responses).
            sender_risk: Optional pre-computed sender risk (for email responses).
        """
        normalized = normalize_for_matching(text)
        context = ScoringContext()

        for rule in self._rules:
            match = self._apply_rule(rule, normalized)
            if match:
                context.add(match)

        risk_score = min(context.total_weight, 100)
        risk_level = self._score_to_level(risk_score)
        categories = context.categories

        matched_signals = [
            MatchedSignal(
                type=m.rule.category,
                match=m.matched_text,
                weight=m.effective_weight,
                reason=m.rule.reason,
            )
            for m in context.rule_matches
        ]

        explanation = self._build_explanation(context, risk_level)
        recommended_action = self._build_recommended_action(categories)

        return AnalysisResult(
            risk_score=risk_score,
            risk_level=risk_level,
            categories=categories,
            matched_signals=matched_signals,
            explanation=explanation,
            recommended_action=recommended_action,
            transcript=transcript,
            sender_risk=sender_risk,
        )

    # ---------------------------------------------------------------- Internals

    def _apply_rule(self, rule: DetectionRule, normalized_text: str) -> RuleMatch | None:
        """Test all patterns for a rule against normalized text.

        Returns a RuleMatch with the first matching snippet if any pattern fires,
        otherwise None.
        """
        for pattern in rule.patterns:
            compiled = re.compile(pattern, re.IGNORECASE)
            matches = compiled.findall(normalized_text)
            if matches:
                # Surface the first match as a string snippet
                first_match = matches[0] if isinstance(matches[0], str) else " ".join(matches[0])
                return RuleMatch(
                    rule=rule,
                    matched_text=first_match.strip() or pattern,
                    hit_count=len(matches),
                )
        return None

    @staticmethod
    def _score_to_level(score: int) -> RiskLevel:
        for threshold, level in RISK_LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return RiskLevel.LOW

    @staticmethod
    def _build_explanation(context: ScoringContext, risk_level: RiskLevel) -> str:
        if not context.rule_matches:
            return "No scam indicators detected in the provided content."

        rule_names = [m.rule.name for m in context.rule_matches]
        categories = context.categories

        if risk_level == RiskLevel.HIGH:
            prefix = "This content contains multiple high-confidence scam indicators"
        elif risk_level == RiskLevel.MEDIUM:
            prefix = "This content contains several potential scam indicators"
        else:
            prefix = "This content contains minor potential scam indicators"

        signals_str = ", ".join(rule_names[:4])
        if len(rule_names) > 4:
            signals_str += f", and {len(rule_names) - 4} more"

        cats_str = ", ".join(categories[:3])
        return (
            f"{prefix}: {signals_str}. "
            f"Detected categories: {cats_str}."
        )

    @staticmethod
    def _build_recommended_action(categories: list[str]) -> str:
        for category in categories:
            action = _CATEGORY_ACTIONS.get(category)
            if action:
                return action
        return _DEFAULT_ACTION


# ------------------------------------------------------------------ Email-aware wrapper


def analyze_email_content(
    subject: str,
    body: str,
    from_address: str | None = None,
    links: list[str] | None = None,
) -> tuple[AnalysisResult, dict]:
    """Analyze email content with sender and link enrichment.

    Combines body+subject text analysis with email-specific checks.
    Returns (AnalysisResult, sender_risk_dict).
    """
    from app.services.analysis.email_checks import analyze_links, analyze_sender

    combined_text = f"{subject} {body}"
    if links:
        combined_text += " " + " ".join(links)

    sender_risk_data = {"is_suspicious": False, "reasons": []}
    if from_address:
        sender_risk_data = analyze_sender(from_address)

    link_reasons = analyze_links(links or [])
    extra_link_weight = min(len(link_reasons) * 10, 30)

    engine = DetectionEngine()
    normalized = normalize_for_matching(combined_text)
    context = ScoringContext()

    for rule in engine._rules:
        match = engine._apply_rule(rule, normalized)
        if match:
            context.add(match)

    # Boost score for suspicious sender/links
    sender_boost = 15 if sender_risk_data["is_suspicious"] else 0
    raw_score = context.total_weight + sender_boost + extra_link_weight
    risk_score = min(raw_score, 100)
    risk_level = DetectionEngine._score_to_level(risk_score)

    sender_risk = SenderRisk(
        is_suspicious=sender_risk_data["is_suspicious"],
        reasons=sender_risk_data["reasons"] + link_reasons,
    ) if (sender_risk_data["is_suspicious"] or link_reasons) else None

    matched_signals = [
        MatchedSignal(
            type=m.rule.category,
            match=m.matched_text,
            weight=m.effective_weight,
            reason=m.rule.reason,
        )
        for m in context.rule_matches
    ]

    explanation = DetectionEngine._build_explanation(context, risk_level)
    categories = context.categories
    recommended_action = DetectionEngine._build_recommended_action(categories)

    result = AnalysisResult(
        risk_score=risk_score,
        risk_level=risk_level,
        categories=categories,
        matched_signals=matched_signals,
        explanation=explanation,
        recommended_action=recommended_action,
        sender_risk=sender_risk,
    )

    return result, sender_risk_data
