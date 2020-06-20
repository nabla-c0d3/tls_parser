from __future__ import absolute_import
from __future__ import print_function

from tls_parser.record_protocol import TlsRecord, TlsSubprotocolMessage, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum


class TlsApplicationDataMessage(TlsSubprotocolMessage):
    def __init__(self, application_data):
        # type: (bytes) -> None
        self.data = application_data

    def to_bytes(self):
        # type: () -> bytes
        return self.data


class TlsApplicationDataRecord(TlsRecord):
    """We make the assumption that an Application record only contains one message, which seems to be the case in the
    real world.
    """

    def __init__(self, record_header, application_data):
        # type: (TlsRecordHeader, TlsApplicationDataMessage) -> None
        super(TlsApplicationDataRecord, self).__init__(record_header, [application_data])

    @classmethod
    def from_parameters(cls, tls_version, application_data):
        # type: (TlsVersionEnum, bytes) -> TlsApplicationDataRecord
        message = TlsApplicationDataMessage(application_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.APPLICATION_DATA, tls_version, message.size)
        return TlsApplicationDataRecord(record_header, message)
