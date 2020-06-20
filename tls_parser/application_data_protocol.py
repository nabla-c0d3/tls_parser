from tls_parser.record_protocol import TlsRecord, TlsSubprotocolMessage, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum


class TlsApplicationDataMessage(TlsSubprotocolMessage):
    pass


class TlsApplicationDataRecord(TlsRecord):
    """We make the assumption that an Application record only contains one message, which seems to be the case in the
    real world.
    """

    def __init__(self, record_header: TlsRecordHeader, application_data: TlsApplicationDataMessage):
        super(TlsApplicationDataRecord, self).__init__(
            record_header=record_header, subprotocol_messages=[application_data]
        )

    @classmethod
    def from_parameters(cls, tls_version: TlsVersionEnum, application_data: bytes) -> "TlsApplicationDataRecord":
        message = TlsApplicationDataMessage(application_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.APPLICATION_DATA, tls_version, message.size)
        return TlsApplicationDataRecord(record_header, message)
