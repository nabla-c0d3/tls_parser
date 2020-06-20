from tls_parser.record_protocol import TlsRecord, TlsRecordHeader, TlsSubprotocolMessage, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple


class TlsChangeCipherSpecRecord(TlsRecord):
    @classmethod
    def from_parameters(cls, tls_version: TlsVersionEnum) -> "TlsChangeCipherSpecRecord":
        ccs_message = TlsSubprotocolMessage(b"\x01")
        record_header = TlsRecordHeader(TlsRecordTypeByte.CHANGE_CIPHER_SPEC, tls_version, ccs_message.size)
        return TlsChangeCipherSpecRecord(record_header, [ccs_message])

    @classmethod
    def from_bytes(cls, raw_byte: bytes) -> Tuple["TlsChangeCipherSpecRecord", int]:
        raise NotImplementedError()
