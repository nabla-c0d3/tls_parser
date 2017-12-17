from __future__ import absolute_import
from __future__ import print_function

import codecs


# TODO(AD): Once we drop support for Python 2, use int.to_bytes() instead?
def int_to_bytes(i):
    # type: (int) -> bytes
    hex_value = '{0:x}'.format(i)
    # Make length of hex_value a multiple of two
    hex_value = '0' * (len(hex_value) % 2) + hex_value
    return codecs.decode(hex_value, 'hex_codec')
