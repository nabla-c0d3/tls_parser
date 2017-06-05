from __future__ import absolute_import
from __future__ import print_function

from enum import Enum


class TlsVersionEnum(Enum):
    SSLV3 = 0
    TLSV1 = 1
    TLSV1_1 = 2
    TLSV1_2 = 3
