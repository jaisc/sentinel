"""Clean / Caution / Dangerous — always with the reasons, never a bare verdict."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable, List

CLEAN = "clean"
CAUTION = "caution"
DANGEROUS = "dangerous"

VERDICT_LABEL = {CLEAN: "Clean", CAUTION: "Caution", DANGEROUS: "Dangerous"}
VERDICT_RANK = {CLEAN: 0, CAUTION: 1, DANGEROUS: 2}

# Points needed for each verdict. A single "danger" reason is 100 on its own;
# several independent "caution" reasons can add up to Dangerous.
CAUTION_AT = 20
DANGEROUS_AT = 100


@dataclass
class Reason:
    code: str            # stable identifier, e.g. "ext_type_mismatch"
    points: int          # contribution to the score
    title: str           # one plain-English line: what we found
    why: str = ""        # why it matters
    observed: bool = True  # True = directly observed; False = inferred / heuristic

    @property
    def level(self) -> str:
        if self.points >= DANGEROUS_AT:
            return DANGEROUS
        if self.points >= CAUTION_AT:
            return CAUTION
        return "info"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level
        return d


def score(reasons: Iterable[Reason]) -> int:
    return max(0, sum(r.points for r in reasons))


def verdict_for(reasons: List[Reason]) -> str:
    s = score(reasons)
    if s >= DANGEROUS_AT:
        return DANGEROUS
    if s >= CAUTION_AT:
        return CAUTION
    return CLEAN


def at_least(verdict: str, minimum: str) -> bool:
    return VERDICT_RANK.get(verdict, 0) >= VERDICT_RANK.get(minimum, 0)
