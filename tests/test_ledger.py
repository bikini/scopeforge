from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scopeforge.ledger import EvidenceLedger
from scopeforge.scope import Scope, ScopeError, create_scope_document, write_scope_document


def make_scope(directory: Path) -> Scope:
    document = create_scope_document(
        engagement="Ledger Test",
        authorized_by="tester",
        expires="2099-01-01T00:00:00Z",
        cidrs=("127.0.0.1/32",),
        domains=("localhost",),
        ports=(80, 8080),
        evidence_dir="evidence",
    )
    return Scope.load(write_scope_document(directory / "scope.json", document))


class LedgerTests(unittest.TestCase):
    def test_append_and_verify_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = make_scope(Path(raw))
            ledger = EvidenceLedger(scope)

            first = ledger.append("unit", "started", {"target": "localhost"})
            second = ledger.append("unit", "completed", {"ok": True})
            verification = ledger.verify()

            self.assertTrue(verification.valid)
            self.assertEqual(2, verification.entries)
            self.assertEqual(second["entry_sha256"], verification.last_hash)
            self.assertIsNone(first["prev_sha256"])

    def test_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = make_scope(Path(raw))
            ledger = EvidenceLedger(scope)
            ledger.append("unit", "completed", {"ok": True})

            lines = ledger.path.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            entry["data"]["ok"] = False
            lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            verification = ledger.verify()
            self.assertFalse(verification.valid)
            self.assertTrue(any("entry_sha256 mismatch" in error for error in verification.errors))

            with self.assertRaises(ScopeError):
                ledger.append("unit", "completed", {"ok": True})


if __name__ == "__main__":
    unittest.main()
