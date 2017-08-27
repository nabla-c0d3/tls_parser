from __future__ import absolute_import
from __future__ import print_function

import struct
from enum import IntEnum
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from tls_parser.tls_version import TlsVersionEnum
from typing import Tuple, List


class TlsHandshakeTypeByte(IntEnum):
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
        bytes += struct.pack('B', self.handshake_type.value)
        # TLS Handshake length - 3 bytes
        bytes += struct.pack('!I', len(self.handshake_data))[1:4]  # We only keep the first 3 out of 4 bytes
        # TLS Handshake message
        bytes += self.handshake_data
        return bytes


class TlsHandshakeRecord(TlsRecord):

    def __init__(self, record_header, handshake_messages):
        # type: (TlsRecordHeader, List[TlsHandshakeMessage]) -> None
        super(TlsHandshakeRecord, self).__init__(record_header, handshake_messages)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeRecord, int]
        header, len_consumed_for_header = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed_for_header::]

        if header.type != TlsRecordTypeByte.HANDSHAKE:
            raise UnknownTypeByte()

        # Try to parse the handshake record - there may be multiple messages packed in the record
        messages = []
        total_len_consumed_for_messages = 0
        while total_len_consumed_for_messages != header.length:
            message, len_consumed_for_message = TlsHandshakeMessage.from_bytes(remaining_bytes)
            messages.append(message)
            total_len_consumed_for_messages += len_consumed_for_message
            remaining_bytes = remaining_bytes[len_consumed_for_message::]

        parsed_record = TlsHandshakeRecord(header, messages)
        return parsed_record, len_consumed_for_header + total_len_consumed_for_messages
