"""Wilson score interval for reporting rates with a small n honestly."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class WilsonCI:
    successes: int
    n: int
    point: float
    low: float
    high: float

    def __str__(self) -> str:
        ci = f"[{self.low:.1%}, {self.high:.1%}]"
        return f"{self.successes}/{self.n} = {self.point:.1%} (95% CI {ci})"


def wilson_interval(successes: int, n: int, z: float = 1.96) -> WilsonCI:
    if n == 0:
        return WilsonCI(0, 0, 0.0, 0.0, 0.0)
    p = successes / n
    denom = 1 + z**2 / n
    center = p + z**2 / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))
    low = max(0.0, (center - margin) / denom)
    high = min(1.0, (center + margin) / denom)
    return WilsonCI(successes, n, p, low, high)
