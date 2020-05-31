from __future__ import absolute_import
from __future__ import print_function

import unittest
from tls_parser.alert_protocol import TlsAlertRecord, TlsAlertSeverityByte
from tls_parser.exceptions import UnknownTlsVersionByte


class TlsAlertRecordTestCase(unittest.TestCase):

    def test_from_bytes(self):
        alert_bytes = b'\x15\x03\x03\x00\x02\x02\x14'
        parsed_record, len_consumed = TlsAlertRecord.from_bytes(alert_bytes)
        self.assertEqual(parsed_record.alert_severity, TlsAlertSeverityByte.FATAL)
        self.assertEqual(parsed_record.alert_description, 0x14)
        self.assertEqual(len_consumed, len(alert_bytes))

    def test_from_bytes_with_invalid_version(self):
        # Related to https://github.com/nabla-c0d3/sslyze/issues/437
        # Some servers put invalid TLS version bytes in the TLS alert they send back
        alert_bytes_with_bad_version = b'\x15\x00\x00\x00\x02\x02('
        with self.assertRaises(UnknownTlsVersionByte):
            TlsAlertRecord.from_bytes(alert_bytes_with_bad_version)
