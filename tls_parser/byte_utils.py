from __future__ import absolute_import
from __future__ import print_function

import codecs
from typing import Optional


# TODO(AD): Once we drop support for Python 2, use int.to_bytes() instead?
def int_to_bytes(i, expected_length=None):
    # type: (int, Optional[int]) -> bytes
    hex_value = "{0:x}".format(i)
    # Make length of hex_value a multiple of two
    hex_value = "0" * (len(hex_value) % 2) + hex_value
    bytes_length = int(len(hex_value) / 2)

    if expected_length and bytes_length < expected_length:
        # Pad to the expected length
        pad_length = expected_length - bytes_length
        hex_value = "0" * 2 * pad_length + hex_value

    return codecs.decode(hex_value, "hex_codec")
