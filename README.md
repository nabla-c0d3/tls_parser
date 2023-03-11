tls_parser
==========

![Run tests](https://github.com/nabla-c0d3/tls_parser/workflows/Run%20tests/badge.svg)
[![PyPI version](https://badge.fury.io/py/tls-parser.svg)](https://badge.fury.io/py/tls-parser)

Small library to parse TLS records; used by [SSLyze](https://github.com/nabla-c0d3/sslyze).

Development environment
-----------------------

To setup a development environment:

```
$ pip install --upgrade pip setuptools wheel
$ pip install -e . 
$ pip install -r requirements-dev.txt
```

The tests can then be run using:

```
$ invoke test
```
