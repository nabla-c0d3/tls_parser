from __future__ import absolute_import
from __future__ import print_function

import unittest

from tls_parser.handshake_protocol import TlsServerHelloDoneRecord, TlsHandshakeRecord, TlsHandshakeTypeByte
from tls_parser.heartbeat_protocol import TlsHeartbeatRequestRecord
from tls_parser.tls_version import TlsVersionEnum


class TlsHeartbeatRequestRecordTestCase(unittest.TestCase):

    def test_to_bytes(self):
        record = TlsHeartbeatRequestRecord.from_parameters(TlsVersionEnum.TLSV1_2, b'123456')
        self.assertTrue(record.to_bytes())
