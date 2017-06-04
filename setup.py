#!/usr/bin/env python

from setuptools import setup
from tls_parser import __version__
from tls_parser import __author__
from tls_parser import __email__

TLS_PARSER_SETUP = {
    'name': 'tls_parser',
    'version': __version__,
    'description': 'TLS handshake parser.',
    'author': __author__,
    'author_email': __email__,
    'packages': ['tls_parser'],
    'extras_require': {':python_version < "3.4"': ['enum34'],
                       ':python_version < "3.5"': ['typing']},
}


if __name__ == "__main__":
    setup(**TLS_PARSER_SETUP)
