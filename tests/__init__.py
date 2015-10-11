from __future__ import absolute_import, print_function
from unittest import defaultTestLoader as loader, TestSuite

def suite():
    import tests.sigv4_test

    ts = TestSuite()
    ts.addTests(tests.sigv4_test.get_test_cases())

    return ts

nosetests = suite
