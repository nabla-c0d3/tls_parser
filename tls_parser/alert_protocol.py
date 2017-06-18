from __future__ import absolute_import
from __future__ import print_function

import struct
from enum import IntEnum
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple


class TlsAlertSeverityByte(IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertMessage(TlsSubprotocolMessage):

    def __init__(self, alert_severity, alert_description):
        # type: (TlsAlertSeverityByte, int) -> None
        self.alert_severity = alert_severity
        # Right now the description is just stored as an int instead of a TlsAlertDescriptionByte
        self.alert_description = alert_description

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsAlertMessage, int]
        if len(raw_bytes) < 2:
            raise NotEnoughData()
        
        alert_severity = TlsAlertSeverityByte(struct.unpack('B', raw_bytes[0:1])[0])
        alert_description = struct.unpack('B', raw_bytes[1:2])[0]
        return TlsAlertMessage(alert_severity, alert_description), 2

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        bytes += struct.pack('B', self.alert_severity.value)
        bytes += struct.pack('B', self.alert_description)
        return bytes


class TlsAlertRecord(TlsRecord):
    def __init__(self, record_header, alert_message):
        # type: (TlsRecordHeader, TlsAlertMessage) -> None
        super(TlsAlertRecord, self).__init__(record_header, alert_message)

    @classmethod
    def from_parameters(cls, tls_version, alert_severity, alert_description):
        # type: (TlsVersionEnum, TlsAlertSeverityByte, int) -> TlsAlertRecord
        alert_message = TlsAlertMessage(alert_severity, alert_description)
        record_header = TlsRecordHeader(TlsRecordTypeByte.ALERT, tls_version, alert_message.size)
        return TlsAlertRecord(record_header, alert_message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsAlertRecord, int]
        header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed::]

        if header.type != TlsRecordTypeByte.ALERT:
            raise UnknownTypeByte()

        message, len_consumed_for_message = TlsAlertMessage.from_bytes(remaining_bytes)
        return TlsAlertRecord(header, message), len_consumed + len_consumed_for_message
