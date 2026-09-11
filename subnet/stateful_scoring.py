import sqlite3
from dataclasses import dataclass, field

from subnet.protocol import (
    ExploitFinding,
    VerificationResult,
)


@dataclass
class FindingCorpus:
    """Tracks which reproduction keys have already been paid.

    By default this is in-memory only, matching the original behavior. That
    means a validator restart silently forgets every previously-verified
    finding, so the same exploit can be paid again after a restart -- a real
    (if bounded by epoch scoping in build_task/make_benchmark_tasks) exploit
    window. Pass storage_path to persist the corpus across restarts:

        FindingCorpus(storage_path="/var/lib/veritensor/corpus.sqlite3")

    Persistence is opt-in and additive: existing call sites that construct
    FindingCorpus() with no arguments are unaffected.
    """

    reproduction_keys: set[str] = field(default_factory=set)
    storage_path: str | None = None
    _conn: sqlite3.Connection | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.storage_path:
            return
        self._conn = sqlite3.connect(self.storage_path, isolation_level=None)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS reproduction_keys ("
            "key TEXT PRIMARY KEY, added_at REAL NOT NULL DEFAULT (strftime('%s','now')))"
        )
        for (key,) in self._conn.execute("SELECT key FROM reproduction_keys"):
            self.reproduction_keys.add(key)

    def is_duplicate(
        self,
        finding: ExploitFinding,
    ) -> bool:
        return (
            finding.reproduction_key
            in self.reproduction_keys
        )

    def add(
        self,
        finding: ExploitFinding,
    ) -> None:
        self.reproduction_keys.add(
            finding.reproduction_key
        )
        if self._conn is not None:
            self._conn.execute(
                "INSERT OR IGNORE INTO reproduction_keys (key) VALUES (?)",
                (finding.reproduction_key,),
            )


def calculate_security_score(
    *,
    severity: str,
    reproducible: bool,
    policy_violation: bool,
    novel: bool,
    efficiency_score: float,
) -> float:

    if not reproducible or not policy_violation or not novel:
        return 0.0

    weights = {
        "NONE": 0.0,
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00,
    }

    severity_weight = weights[
        severity
    ]

    novelty_weight = 1.0

    return max(
        0.0,
        min(
            1.0,
            severity_weight
            * (
                0.45
                + 0.25 * novelty_weight
                + 0.30 * efficiency_score
            ),
        ),
    )


def calculate_reward(
    verification: VerificationResult,
) -> float:
    return verification.security_score
