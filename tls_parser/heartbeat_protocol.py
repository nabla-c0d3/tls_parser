from __future__ import absolute_import
from __future__ import print_function

import struct
from enum import IntEnum
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple


class TlsHeartbeatTypeByte(IntEnum):
    REQUEST = 0x01
    RESPONSE = 0x02


class TlsHeartbeatMessage(TlsSubprotocolMessage):

    def __init__(self, hearbeat_type, heartbeat_data):
        # type: (TlsHeartbeatTypeByte, bytes) -> None
        self.type = hearbeat_type
        self.data = heartbeat_data

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHeartbeatMessage, int]
        raise NotImplementedError()

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        # Heartbeat message type - 1 byte
        bytes += struct.pack('B', self.type.value)
        # Heartbeat message length - 2 bytes
        bytes += struct.pack('!H', len(self.data))
        # Heartbead message data
        bytes += self.data
        # Padding is not handled
        return bytes


class TlsHeartbeatRequestRecord(TlsRecord):
    """https://tools.ietf.org/html/rfc6520.
    struct {
      HeartbeatMessageType type;
      uint16 payload_length;
      opaque payload[HeartbeatMessage.payload_length];
      opaque padding[padding_length];
    } HeartbeatMessage;
    """

    def __init__(self, record_header, heartbeat_message):
        # type: (TlsRecordHeader, TlsHeartbeatMessage) -> None
        super(TlsHeartbeatRequestRecord, self).__init__(record_header, [heartbeat_message])

    @classmethod
    def from_parameters(cls, tls_version, heartbeat_data):
        # type: (TlsVersionEnum, bytes) -> TlsHeartbeatRequestRecord
        message = TlsHeartbeatMessage(TlsHeartbeatTypeByte.REQUEST, heartbeat_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.HEARTBEAT, tls_version, message.size)
        return TlsHeartbeatRequestRecord(record_header, message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHeartbeatRequestRecord, int]
        raise NotImplementedError()