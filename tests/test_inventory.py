from __future__ import annotations

import unittest

from scopeforge.inventory import build_inventory, diff_inventories


class InventoryTests(unittest.TestCase):
    def test_build_inventory_from_completed_events(self) -> None:
        events = [
            {
                "ts": "2026-01-01T00:00:00Z",
                "action": "tcp_scan",
                "status": "completed",
                "data": {
                    "results": [
                        {"host": "127.0.0.1", "port": 443, "state": "open"},
                        {"host": "127.0.0.1", "port": 22, "state": "closed"},
                    ]
                },
            },
            {
                "ts": "2026-01-01T00:01:00Z",
                "action": "http_probe",
                "status": "completed",
                "data": {
                    "results": [
                        {
                            "url": "https://localhost/",
                            "final_url": "https://localhost/",
                            "status": 200,
                            "title": "Lab",
                            "findings": [{"id": "missing-csp", "severity": "low"}],
                        }
                    ]
                },
            },
            {
                "ts": "2026-01-01T00:02:00Z",
                "action": "tls_probe",
                "status": "completed",
                "data": {
                    "results": [
                        {
                            "host": "localhost",
                            "port": 443,
                            "state": "tls",
                            "tls_version": "TLSv1.3",
                            "cert_sha256": "abc",
                            "not_after": "2099-01-01T00:00:00Z",
                        }
                    ]
                },
            },
        ]

        inventory = build_inventory(events)

        self.assertEqual(2, inventory["summary"]["asset_count"])
        self.assertEqual(3, inventory["summary"]["service_count"])
        by_host = {asset["host"]: asset for asset in inventory["assets"]}
        self.assertEqual([443], by_host["127.0.0.1"]["open_ports"])
        self.assertIn("443/https", by_host["localhost"]["services"])
        self.assertIn("443/tls", by_host["localhost"]["services"])

    def test_diff_inventories_reports_added_and_removed_services(self) -> None:
        before = {
            "assets": [
                {"host": "a.lab", "services": {"80/http": {}}},
                {"host": "b.lab", "services": {"443/tls": {}}},
            ]
        }
        after = {
            "assets": [
                {"host": "a.lab", "services": {"80/http": {}, "443/https": {}}},
                {"host": "c.lab", "services": {"8080/http": {}}},
            ]
        }

        diff = diff_inventories(before, after)

        self.assertEqual([{"host": "a.lab", "service": "443/https"}, {"host": "c.lab", "service": "8080/http"}], diff["added_services"])
        self.assertEqual([{"host": "b.lab", "service": "443/tls"}], diff["removed_services"])
        self.assertEqual(1, diff["unchanged_service_count"])


if __name__ == "__main__":
    unittest.main()
