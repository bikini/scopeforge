from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scopeforge.scope import Scope, ScopeError, create_scope_document, write_scope_document


def write_test_scope(directory: Path, **overrides: object) -> Path:
    document = create_scope_document(
        engagement="Unit Test",
        authorized_by="tester",
        expires="2099-01-01T00:00:00Z",
        cidrs=("192.168.56.0/24",),
        domains=("localhost", "*.lab.example"),
        ports=(80, 443, 8080, 8443),
        evidence_dir="evidence",
        rate_limit_per_second=100,
        max_hosts=32,
    )
    document.update(overrides)
    return write_scope_document(directory / "scope.json", document)


class ScopeTests(unittest.TestCase):
    def test_allows_cidr_ip_domain_and_url_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = Scope.load(write_test_scope(Path(raw)))

            self.assertTrue(scope.allows_target("192.168.56.10").allowed)
            self.assertTrue(scope.allows_target("192.168.56.0/28").allowed)
            self.assertTrue(scope.allows_target("api.lab.example").allowed)
            self.assertTrue(scope.allows_target("https://api.lab.example:8443/path").allowed)

    def test_blocks_out_of_scope_targets(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = Scope.load(write_test_scope(Path(raw)))

            self.assertFalse(scope.allows_target("192.168.57.10").allowed)
            self.assertFalse(scope.allows_target("example.org").allowed)
            self.assertFalse(scope.allows_target("lab.example").allowed)

    def test_requires_explicit_url_port(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            scope = Scope.load(write_test_scope(Path(raw)))

            scope.require_url("https://api.lab.example:8443/")
            with self.assertRaises(ScopeError):
                scope.require_url("https://api.lab.example:22/")

    def test_expired_scope_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = write_test_scope(Path(raw), expires="2001-01-01T00:00:00Z")
            scope = Scope.load(path)

            with self.assertRaises(ScopeError):
                scope.allows_target("192.168.56.10")

    def test_invalid_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "scope.json"
            path.write_text(json.dumps({"engagement": "missing fields"}), encoding="utf-8")

            with self.assertRaises(ScopeError):
                Scope.load(path)


if __name__ == "__main__":
    unittest.main()
