import struct
from enum import Enum
from enum import IntEnum
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte, UnknownTlsVersionByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple, Sequence


class TlsRecordTlsVersionBytes(Enum):
    SSLV3 = b"\x03\x00"
    TLSV1 = b"\x03\x01"
    TLSV1_1 = b"\x03\x02"
    TLSV1_2 = b"\x03\x03"


class TlsRecordTypeByte(IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsRecordHeader:
    def __init__(self, record_type: TlsRecordTypeByte, tls_version: TlsVersionEnum, record_length: int) -> None:
        self.type = record_type
        self.tls_version = tls_version
        self.length = record_length

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsRecordHeader", int]:
        if len(raw_bytes) < 5:
            raise NotEnoughData()

        record_type = TlsRecordTypeByte(struct.unpack("B", raw_bytes[0:1])[0])

        try:
            tls_version = TlsRecordTlsVersionBytes(raw_bytes[1:3])
        except ValueError as e:
            raise UnknownTlsVersionByte(e.args[0], record_type)

        record_length = struct.unpack("!H", raw_bytes[3:5])[0]
        return TlsRecordHeader(record_type, TlsVersionEnum[tls_version.name], record_length), 5

    def to_bytes(self) -> bytes:
        as_bytes = b""
        # TLS Record type - 1 byte
        as_bytes += struct.pack("B", self.type.value)
        # TLS version - 2 bytes
        as_bytes += TlsRecordTlsVersionBytes[self.tls_version.name].value
        # Length - 2 bytes
        as_bytes += struct.pack("!H", self.length)
        return as_bytes


class TlsSubprotocolMessage:
    # Handshake, Alert, etc.

    def __init__(self, message_data: bytes) -> None:
        self.message_data = message_data

    def to_bytes(self) -> bytes:
        return self.message_data

    @property
    def size(self) -> int:
        return len(self.to_bytes())


class TlsRecord:
    def __init__(self, record_header: TlsRecordHeader, subprotocol_messages: Sequence[TlsSubprotocolMessage]) -> None:
        self.header = record_header

        # Several messages can be concatenated into a single record; the messages must belong to the same subprotocol
        # Hence, in practice this only seems to apply to the handshake protocol
        if self.header.type != TlsRecordTypeByte.HANDSHAKE and len(subprotocol_messages) != 1:
            raise ValueError("Received multiple subprotocol messages for a non-handshake record")

        self.subprotocol_messages = subprotocol_messages

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsRecord", int]:
        record_header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)

        # Try to parse the record
        if record_header.type not in TlsRecordTypeByte:
            raise UnknownTypeByte()

        record_data = raw_bytes[len_consumed : len_consumed + record_header.length]  # noqa: E203
        if len(record_data) < record_header.length:
            raise NotEnoughData()

        # We do not attempt to parse the message - the data may actually contain multiple messages
        message = TlsSubprotocolMessage(record_data)
        return TlsRecord(record_header, [message]), len_consumed + record_header.length

    def to_bytes(self) -> bytes:
        as_bytes = b""
        as_bytes += self.header.to_bytes()
        for message in self.subprotocol_messages:
            as_bytes += message.to_bytes()
        return as_bytes
