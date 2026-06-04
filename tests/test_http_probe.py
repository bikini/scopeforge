from __future__ import annotations

import unittest

from scopeforge.http_probe import analyze_http_headers


class HttpAnalysisTests(unittest.TestCase):
    def test_https_missing_security_headers_are_flagged(self) -> None:
        findings = analyze_http_headers("https://localhost/", {"Server": "nginx/1.26"})
        finding_ids = {finding["id"] for finding in findings}

        self.assertIn("missing-hsts", finding_ids)
        self.assertIn("missing-csp", finding_ids)
        self.assertIn("missing-x-content-type-options", finding_ids)
        self.assertIn("missing-clickjacking-control", finding_ids)
        self.assertIn("server-version-disclosure", finding_ids)

    def test_security_headers_reduce_findings(self) -> None:
        findings = analyze_http_headers(
            "https://localhost/",
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "Server": "frontdoor",
            },
        )

        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
