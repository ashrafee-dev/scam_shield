"""Internal models for the analysis engine.

DetectionRule drives the scoring engine. Rules are declarative — they
define what to look for, how much it weighs, and what category it belongs to.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionRule:
    """A single detection rule applied by the scoring engine.

    Attributes:
        id: Unique rule identifier.
        name: Human-readable rule name.
        patterns: List of regex patterns (case-insensitive) to match.
        weight: Contribution to the aggregate risk score (0–100 scale).
        category: Scam category this rule belongs to.
        reason: Human-readable explanation surfaced in the API response.
        deduplicate: If True, only count this rule once even if it matches multiple times.
    """

    id: str
    name: str
    patterns: list[str]
    weight: int
    category: str
    reason: str
    deduplicate: bool = True


@dataclass
class RuleMatch:
    """The result of a single rule matching against input text."""

    rule: DetectionRule
    matched_text: str
    hit_count: int = 1

    @property
    def effective_weight(self) -> int:
        """Weight after applying deduplication logic."""
        if self.rule.deduplicate:
            return self.rule.weight
        return self.rule.weight * min(self.hit_count, 3)


@dataclass
class ScoringContext:
    """Accumulates rule matches during analysis of a single input."""

    rule_matches: list[RuleMatch] = field(default_factory=list)

    def add(self, match: RuleMatch) -> None:
        self.rule_matches.append(match)

    @property
    def total_weight(self) -> int:
        return sum(m.effective_weight for m in self.rule_matches)

    @property
    def categories(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for m in self.rule_matches:
            cat = m.rule.category
            if cat not in seen:
                seen.add(cat)
                result.append(cat)
        return result
