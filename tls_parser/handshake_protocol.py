from __future__ import absolute_import
from __future__ import print_function

import struct
from enum import Enum
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple


class TlsHandshakeTypeByte(Enum):
   HELLO_REQUEST = 0x00
   CLIENT_HELLO = 0x01
   SERVER_HELLO = 0x02
   CERTIFICATE = 0x0b
   SERVER_KEY_EXCHANGE = 0x0c
   CERTIFICATE_REQUEST = 0x0d
   SERVER_DONE = 0x0e
   CERTIFICATE_VERIFY = 0x0f
   CLIENT_KEY_EXCHANGE = 0x10
   FINISHED = 0x14


class TlsHandshakeMessage(TlsSubprotocolMessage):
    """The payload of a handshake record.
    """

    def __init__(self, handshake_type, handshake_data):
        # type: (TlsHandshakeTypeByte, bytes) -> None
        self.handshake_type = handshake_type
        self.handshake_data = handshake_data

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeMessage, int]
        if len(raw_bytes) < 4:
            raise NotEnoughData()

        handshake_type = TlsHandshakeTypeByte(struct.unpack('B', raw_bytes[0:1])[0])
        message_length = struct.unpack('!I', b'\x00' + raw_bytes[1:4])[0]
        message = raw_bytes[4:message_length+4]
        if len(message) < message_length:
            raise NotEnoughData()

        return TlsHandshakeMessage(handshake_type, message), 4 + message_length

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        # TLS Handshake type - 1 byte
        bytes += struct.pack('B', [self.handshake_type.value])
        # TLS Handshake length - 3 bytes
        bytes += struct.pack('!I', len(self.handshake_data))[1:4]  # We only keep the first 3 out of 4 bytes
        # TLS Handshake message
        bytes += self.handshake_data
        return bytes


class TlsHandshakeRecord(TlsRecord):

    def __init__(self, record_header, handshake_message):
        # type: (TlsRecordHeader, TlsHandshakeMessage) -> None
        super(TlsHandshakeRecord, self).__init__(record_header, handshake_message)

    @classmethod
    def from_parameters(cls, tls_version, handshake_type, handshake_data):
        handshake_message = TlsHandshakeMessage(handshake_type, handshake_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.HANDSHAKE, tls_version, handshake_message.size)
        return TlsHandshakeRecord(record_header, handshake_message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeRecord, int]
        header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed::]

        if header.type != TlsRecordTypeByte.HANDSHAKE:
            raise UnknownTypeByte()

        # Try to parse the handshake record
        message, len_consumed_for_message = TlsHandshakeMessage.from_bytes(remaining_bytes)
        handshake_type = TlsHandshakeTypeByte(struct.unpack('B', remaining_bytes[0:1])[0])
        if handshake_type == TlsHandshakeTypeByte.SERVER_DONE:
            parsed_record = TlsServerHelloDoneRecord(header)
        elif handshake_type in TlsHandshakeTypeByte:
            # Valid handshake type but we don't have the code to parse it right now
            parsed_record = TlsHandshakeRecord(header, message)
        else:
            raise UnknownTypeByte()

        return parsed_record, len_consumed + len_consumed_for_message


class TlsServerHelloDoneRecord(TlsHandshakeRecord):

    def __init__(self, record_header):
        # A ServerHelloDone does not carry any actual data
        super(TlsServerHelloDoneRecord, self).__init__(record_header,
                                                       TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_DONE, b''))

    @classmethod
    def from_parameters(cls, tls_version):
        # type: (TlsVersionEnum) -> TlsServerHelloDoneRecord
        record_header = TlsRecordHeader(TlsRecordTypeByte.SERVER_DONE, tls_version, 0)
        return TlsServerHelloDoneRecord(record_header)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsServerHelloDoneRecord, int]
        parsed_record, len_consumed = super(TlsServerHelloDoneRecord, cls).from_bytes(raw_bytes)

        if parsed_record.subprotocol_message.handshake_type != TlsHandshakeTypeByte.SERVER_DONE:
            raise UnknownTypeByte()

        return parsed_record, len_consumed
    