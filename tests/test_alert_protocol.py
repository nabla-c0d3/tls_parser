from __future__ import absolute_import
from __future__ import print_function

import unittest
from tls_parser.alert_protocol import TlsAlertRecord, TlsAlertSeverityByte


class TlsAlertRecordTestCase(unittest.TestCase):

    ALERT_BYTES = b'\x15\x03\x03\x00\x02\x02\x14'

    def test_from_bytes(self):
        parsed_record, len_consumed = TlsAlertRecord.from_bytes(self.ALERT_BYTES)
        self.assertEqual(parsed_record.alert_severity, TlsAlertSeverityByte.FATAL)
        self.assertEqual(parsed_record.alert_description, 0x14)
        self.assertEqual(len_consumed, len(self.ALERT_BYTES))
