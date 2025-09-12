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
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    packages=["tls_parser"],
    python_requires=">=3.8",
)
