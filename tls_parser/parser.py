from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.exceptions import UnknownTypeByte
from tls_parser.handshake_protocol import TlsHandshakeRecord
from tls_parser.record_protocol import TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from typing import Tuple


class TlsRecordParser:
    @staticmethod
    def parse_bytes(raw_bytes: bytes) -> Tuple[TlsRecord, int]:
        record_header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)

        # Try to parse the record
        if record_header.type == TlsRecordTypeByte.HANDSHAKE:
            return TlsHandshakeRecord.from_bytes(raw_bytes)
        elif record_header.type == TlsRecordTypeByte.ALERT:
            return TlsAlertRecord.from_bytes(raw_bytes)
        elif record_header.type in TlsRecordTypeByte:
            # Valid record type but we don't have the code to parse it right now
            return TlsRecord.from_bytes(raw_bytes)
        else:
            # Unknown type
            raise UnknownTypeByte()
