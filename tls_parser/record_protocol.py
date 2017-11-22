from __future__ import absolute_import
from __future__ import print_function

import struct
from enum import Enum
from enum import IntEnum
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple, List


class TlsRecordTlsVersionBytes(Enum):
    SSLV3 = b'\x03\x00'
    TLSV1 = b'\x03\x01'
    TLSV1_1 = b'\x03\x02'
    TLSV1_2 = b'\x03\x03'


class TlsRecordTypeByte(IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsRecordHeader(object):
    def __init__(self, record_type, tls_version, record_length):
        # type: (TlsRecordTypeByte, TlsVersionEnum, int) -> None
        self.type = record_type
        self.tls_version = tls_version
        self.length = record_length

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsRecordHeader, int]
        if len(raw_bytes) < 5:
            raise NotEnoughData()

        record_type = TlsRecordTypeByte(struct.unpack('B', raw_bytes[0:1])[0])
        tls_version = TlsRecordTlsVersionBytes(raw_bytes[1:3])
        record_length = struct.unpack('!H', raw_bytes[3:5])[0]
        return TlsRecordHeader(record_type, tls_version, record_length), 5

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        # TLS Record type - 1 byte
        bytes += struct.pack('B', self.type.value)
        # TLS version - 2 bytes
        bytes += TlsRecordTlsVersionBytes[self.tls_version.name].value
        # Length - 2 bytes
        bytes += struct.pack('!H', self.length)
        return bytes


class TlsRecord(object):
    def __init__(self, record_header, subprotocol_messages):
        # type: (TlsRecordHeader, List[TlsSubprotocolMessage]) -> None
        self.header = record_header

        # Several messages can be concatenated into a single record; the messages must belong to the same subprotocol
        # Hence, in practice this only seems to apply to the handshake protocol
        if self.header.type != TlsRecordTypeByte.HANDSHAKE and len(subprotocol_messages) != 1:
            raise ValueError('Received multiple subprotocol messages for a non-handshake record')

        self.subprotocol_messages = subprotocol_messages

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsRecord, int]
        record_header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)

        # Try to parse the record
        if record_header.type not in TlsRecordTypeByte:
            raise UnknownTypeByte()

        record_data = raw_bytes[len_consumed:len_consumed+record_header.length]
        if len(record_data) < record_header.length:
            raise NotEnoughData()

        # We do not attempt to parse the message - the data may actually contain multiple messages
        message = TlsSubprotocolMessage(record_data)
        return TlsRecord(record_header, [message]), len_consumed + record_header.length

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        bytes += self.header.to_bytes()
        for message in self.subprotocol_messages:
            bytes += message.to_bytes()
        return bytes


class TlsSubprotocolMessage(object):
    # Handshake, Alert, etc.

    def __init__(self, message_data):
        # type: (bytes) -> None
        self.message_data = message_data

    def to_bytes(self):
        # type: () -> bytes
        return self.message_data

    @property
    def size(self):
        # type: () -> int
        return len(self.to_bytes())
