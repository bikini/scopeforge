from __future__ import annotations

import unittest

from scopeforge.tls_probe import TlsProbeResult, _cert_timestamp, _name_tuple_to_dict


class TlsProbeTests(unittest.TestCase):
    def test_certificate_name_tuple_is_flattened(self) -> None:
        name = ((("commonName", "localhost"),), (("organizationName", "Lab"),))

        self.assertEqual({"commonName": "localhost", "organizationName": "Lab"}, _name_tuple_to_dict(name))

    def test_certificate_timestamp_is_iso_utc(self) -> None:
        self.assertEqual("2099-01-01T00:00:00Z", _cert_timestamp("Jan  1 00:00:00 2099 GMT"))

    def test_tls_probe_result_is_json_ready(self) -> None:
        result = TlsProbeResult(host="localhost", port=443, state="tls", tls_version="TLSv1.3")

        self.assertEqual("localhost", result.as_dict()["host"])
        self.assertEqual([], result.as_dict()["subject_alt_names"])


if __name__ == "__main__":
    unittest.main()
