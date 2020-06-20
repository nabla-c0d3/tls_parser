import pytest

from tls_parser.alert_protocol import TlsAlertRecord, TlsAlertSeverityByte
from tls_parser.exceptions import UnknownTlsVersionByte


class TestTlsAlertRecord:
    def test_from_bytes(self):
        alert_bytes = b"\x15\x03\x03\x00\x02\x02\x14"
        parsed_record, len_consumed = TlsAlertRecord.from_bytes(alert_bytes)
        assert parsed_record.alert_severity == TlsAlertSeverityByte.FATAL
        assert parsed_record.alert_description == 0x14
        assert len_consumed == len(alert_bytes)

    def test_from_bytes_with_invalid_version(self):
        # Related to https://github.com/nabla-c0d3/sslyze/issues/437
        # Some servers put invalid TLS version bytes in the TLS alert they send back
        alert_bytes_with_bad_version = b"\x15\x00\x00\x00\x02\x02("
        with pytest.raises(UnknownTlsVersionByte):
            TlsAlertRecord.from_bytes(alert_bytes_with_bad_version)
