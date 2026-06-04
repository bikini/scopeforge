from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
import hashlib
import json
from typing import Any

from . import __version__
from .scope import Scope, ScopeError, utc_now


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: dict[str, Any]) -> str:
    material = dict(entry)
    material.pop("entry_sha256", None)
    return hashlib.sha256(_canonical_json(material)).hexdigest()


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    entries: int
    last_hash: str | None
    errors: tuple[str, ...]


class EvidenceLedger:
    def __init__(self, scope: Scope, path: str | Path | None = None) -> None:
        self.scope = scope
        self.path = Path(path).expanduser().resolve() if path else scope.evidence_dir / "ledger.jsonl"

    def append(self, action: str, status: str, data: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        verification = self.verify()
        if not verification.valid:
            raise ScopeError(f"ledger verification failed; refusing to append to {self.path}")
        previous = verification.last_hash
        entry: dict[str, Any] = {
            "ts": utc_now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool": "scopeforge",
            "tool_version": __version__,
            "engagement": self.scope.engagement,
            "scope_file": str(self.scope.path),
            "action": action,
            "status": status,
            "data": data,
            "prev_sha256": previous,
        }
        entry["entry_sha256"] = _entry_hash(entry)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return entry

    def read_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ScopeError(f"ledger JSON error on line {line_no}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ScopeError(f"ledger line {line_no} is not an object")
                events.append(value)
        return events

    def verify(self) -> LedgerVerification:
        return verify_ledger_path(self.path)


def verify_ledger_path(path: str | Path) -> LedgerVerification:
    ledger_path = Path(path).expanduser().resolve()
    if not ledger_path.exists():
        return LedgerVerification(True, 0, None, ())

    errors: list[str] = []
    previous: str | None = None
    entries = 0

    with ledger_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            entries += 1
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: invalid JSON: {exc}")
                previous = None
                continue
            if not isinstance(entry, dict):
                errors.append(f"line {line_no}: expected JSON object")
                previous = None
                continue

            expected_prev = previous
            actual_prev = entry.get("prev_sha256")
            if actual_prev != expected_prev:
                errors.append(
                    f"line {line_no}: prev_sha256 mismatch "
                    f"(expected {expected_prev!r}, got {actual_prev!r})"
                )

            expected_hash = _entry_hash(entry)
            actual_hash = entry.get("entry_sha256")
            if actual_hash != expected_hash:
                errors.append(
                    f"line {line_no}: entry_sha256 mismatch "
                    f"(expected {expected_hash}, got {actual_hash!r})"
                )

            previous = actual_hash if isinstance(actual_hash, str) else expected_hash

    return LedgerVerification(not errors, entries, previous, tuple(errors))
