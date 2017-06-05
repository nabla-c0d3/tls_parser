#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function

import sys
import unittest
import os


def main(test_path):
    sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'lib'))
    suite = unittest.loader.TestLoader().discover(test_path)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exit_code = 0 if result.wasSuccessful() else 1
    sys.exit(exit_code)

if __name__ == '__main__':
    main('tests')

