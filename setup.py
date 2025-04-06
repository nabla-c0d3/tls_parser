from setuptools import setup
from tls_parser import __version__
from tls_parser import __author__
from tls_parser import __email__

setup(
    name="tls_parser",
    version=__version__,
    description="Small library to parse TLS records.",
    author=__author__,
    author_email=__email__,
    url="https://github.com/nabla-c0d3/tls_parser",
    packages=["tls_parser"],
    python_requires=">=3.8",
)
