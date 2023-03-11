import struct
from enum import IntEnum

from tls_parser.tls_version import TlsVersionEnum

from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from tls_parser.record_protocol import TlsSubprotocolMessage, TlsRecord, TlsRecordHeader, TlsRecordTypeByte
from typing import Tuple, Sequence


class TlsHandshakeTypeByte(IntEnum):
    HELLO_REQUEST = 0x00
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    HELLO_VERIFY_REQUEST = 0x03
    NEW_SESSION_TICKET = 0x04
    CERTIFICATE = 0x0B
    SERVER_KEY_EXCHANGE = 0x0C
    CERTIFICATE_REQUEST = 0x0D
    SERVER_DONE = 0x0E
    CERTIFICATE_VERIFY = 0x0F
    CLIENT_KEY_EXCHANGE = 0x10
    FINISHED = 0x14
    CERTIFICATE_STATUS = 0x16


class TlsHandshakeMessage(TlsSubprotocolMessage):
    """The payload of a handshake record."""

    def __init__(self, handshake_type: TlsHandshakeTypeByte, handshake_data: bytes) -> None:
        # Recreate the raw message as bytes
        full_message_data = b""
        # TLS Handshake type - 1 byte
        full_message_data += struct.pack("B", handshake_type.value)
        # TLS Handshake length - 3 bytes
        full_message_data += struct.pack("!I", len(handshake_data))[1:4]  # We only keep the first 3 out of 4 bytes
        # TLS Handshake message
        full_message_data += handshake_data
        super().__init__(full_message_data)

        self.handshake_type = handshake_type
        self.handshake_data = handshake_data

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHandshakeMessage", int]:
        if len(raw_bytes) < 4:
            raise NotEnoughData()

        handshake_type = TlsHandshakeTypeByte(struct.unpack("B", raw_bytes[0:1])[0])
        message_length = struct.unpack("!I", b"\x00" + raw_bytes[1:4])[0]
        message = raw_bytes[4 : message_length + 4]  # noqa: E203
        if len(message) < message_length:
            raise NotEnoughData()

        return TlsHandshakeMessage(handshake_type, message), 4 + message_length


class TlsHandshakeRecord(TlsRecord):
    def __init__(self, record_header: TlsRecordHeader, handshake_messages: Sequence[TlsHandshakeMessage]) -> None:
        super().__init__(record_header=record_header, subprotocol_messages=handshake_messages)

        # TODO(AD): Fix the interface instead of using an annotation
        self.subprotocol_messages: Sequence[TlsHandshakeMessage]

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Tuple["TlsHandshakeRecord", int]:
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


class TlsRsaClientKeyExchangeRecord(TlsHandshakeRecord):
    @classmethod
    def from_parameters(
        cls, tls_version: TlsVersionEnum, public_exponent: int, public_modulus: int, pre_master_secret_with_padding: int
    ) -> TlsHandshakeRecord:
        cke_bytes = b""

        # Encrypt the pre_master_secret
        encrypted_pms = pow(pre_master_secret_with_padding, public_exponent, public_modulus)
        # Add it to the message but pad it so that its length is the same as the length of the modulus
        modulus_length_in_bytes = (public_modulus.bit_length() + 7) // 8
        encrypted_pms_bytes = encrypted_pms.to_bytes(length=modulus_length_in_bytes, byteorder="big")

        # Per RFC 5246: the RSA-encrypted PreMasterSecret in a ClientKeyExchange is preceded by two length bytes
        # These bytes are redundant in the case of RSA because the EncryptedPreMasterSecret is the only data in the
        # ClientKeyExchange
        msg_size = struct.pack("!I", len(encrypted_pms_bytes))[2:4]  # Length is two bytes
        cke_bytes += msg_size
        cke_bytes += encrypted_pms_bytes
        msg = TlsHandshakeMessage(TlsHandshakeTypeByte.CLIENT_KEY_EXCHANGE, cke_bytes)

        # Build the header
        header = TlsRecordHeader(TlsRecordTypeByte.HANDSHAKE, tls_version, len(msg.to_bytes()))
        return TlsRsaClientKeyExchangeRecord(header, [msg])
