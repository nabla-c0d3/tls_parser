from tls_parser.handshake_protocol import TlsHandshakeRecord


# Parse a server hello message
SERVER_HELLO_BYTES = (
    b"\x16\x03\x03\x00F\x02\x00\x00B\x03\x03\xf2\x00\xfd\x10\xea\x9e\x02\xe5\xc0\x83\x02T7"
    b"\xa7o\xf1\xdb\xd4\x8e\xc8>/\x9c\xeei\xb5\x9fi\xf9\x9e s\x00\xc0/\x00\x00\x1a\x00\x00"
    b"\x00\x00\xff\x01\x00\x01\x00\x00\x0b\x00\x04\x03\x00\x01\x02\x00#\x00\x00\x00\x0f\x00"
    b"\x01\x01"
)

parsed_record, len_consumed = TlsHandshakeRecord.from_bytes(SERVER_HELLO_BYTES)
print(parsed_record.header.tls_version)
print(parsed_record.header.type)
print(parsed_record.header.length)
print(parsed_record.subprotocol_messages[0].handshake_type)
