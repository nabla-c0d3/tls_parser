import struct
from enum import IntEnum
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple


class TlsHeartbeatTypeByte(IntEnum):
    REQUEST = 0x01
    RESPONSE = 0x02


class TlsHeartbeatMessage(TlsSubprotocolMessage):
    def __init__(self, hearbeat_type: TlsHeartbeatTypeByte, heartbeat_data: bytes) -> None:
        # Recreate the raw message as bytes
        full_message_data = b""
        # Heartbeat message type - 1 byte
        full_message_data += struct.pack("B", hearbeat_type.value)
        # Heartbeat message length - 2 bytes
        full_message_data += struct.pack("!H", len(heartbeat_data))
        # Heartbead message data
        full_message_data += heartbeat_data
        # Padding is not handled
        super().__init__(full_message_data)

        # TODO(AD): Rename to self.hearbeat_type and self.heartbeat_data to mirror convention in the handshake protocol
        self.type = hearbeat_type
        self.data = heartbeat_data

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHeartbeatMessage", int]:
        raise NotImplementedError()


class TlsHeartbeatRequestRecord(TlsRecord):
    """https://tools.ietf.org/html/rfc6520.
    struct {
      HeartbeatMessageType type;
      uint16 payload_length;
      opaque payload[HeartbeatMessage.payload_length];
      opaque padding[padding_length];
    } HeartbeatMessage;
    """

    def __init__(self, record_header: TlsRecordHeader, heartbeat_message: TlsHeartbeatMessage) -> None:
        super().__init__(record_header=record_header, subprotocol_messages=[heartbeat_message])

    @classmethod
    def from_parameters(cls, tls_version: TlsVersionEnum, heartbeat_data: bytes) -> "TlsHeartbeatRequestRecord":
        message = TlsHeartbeatMessage(TlsHeartbeatTypeByte.REQUEST, heartbeat_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.HEARTBEAT, tls_version, message.size)
        return TlsHeartbeatRequestRecord(record_header, message)

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHeartbeatRequestRecord", int]:
        raise NotImplementedError()
