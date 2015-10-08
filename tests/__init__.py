from __future__ import absolute_import, print_function
from unittest import defaultTestLoader as loader, TestSuite

def suite():
    import tests.sigv4_test

    ts = TestSuite()
    for module in [
            tests.sigv4_test,
    ]:
        ts.addTest(loader.loadTestsFromModule(module))

    return ts
