from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scopeforge.scanner import expand_targets
from scopeforge.scope import Scope, ScopeError, create_scope_document, write_scope_document


def make_scope(directory: Path, max_hosts: int = 16) -> Scope:
    document = create_scope_document(
        engagement="Scanner Test",
        authorized_by="tester",
        expires="2099-01-01T00:00:00Z",
        cidrs=("192.168.56.0/24",),
        domains=("localhost",),
        ports=(80, 443),
        evidence_dir="evidence",
        max_hosts=max_hosts,
    )
    return Scope.load(write_scope_document(directory / "scope.json", document))


class ScannerTests(unittest.TestCase):
    def test_expand_in_scope_cidr(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = make_scope(Path(raw))

            self.assertEqual(("192.168.56.1", "192.168.56.2"), expand_targets(scope, ["192.168.56.0/30"]))

    def test_expand_refuses_large_cidr(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = make_scope(Path(raw), max_hosts=2)

            with self.assertRaises(ScopeError):
                expand_targets(scope, ["192.168.56.0/29"])

    def test_expand_refuses_out_of_scope_cidr(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = make_scope(Path(raw))

            with self.assertRaises(ScopeError):
                expand_targets(scope, ["192.168.57.0/30"])


if __name__ == "__main__":
    unittest.main()
