from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tls_parser.record_protocol import TlsRecordTypeByte


class NotEnoughData(ValueError):
    pass


class UnknownTypeByte(ValueError):
    pass


class UnknownTlsVersionByte(ValueError):
    def __init__(self, message: str, record_type: "TlsRecordTypeByte") -> None:
        super(ValueError, self).__init__(message)
        self.record_type = record_type
