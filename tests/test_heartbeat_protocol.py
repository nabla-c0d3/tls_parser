from tls_parser.heartbeat_protocol import TlsHeartbeatRequestRecord
from tls_parser.tls_version import TlsVersionEnum


class TestTlsHeartbeatRequestRecord:
    def test_to_bytes(self):
        record = TlsHeartbeatRequestRecord.from_parameters(TlsVersionEnum.TLSV1_2, b"123456")
        assert record.to_bytes()
