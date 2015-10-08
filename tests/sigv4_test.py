#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import kdist.sigv4 as sigv4
from unittest import TestCase

class SigV4Test(TestCase):
    def test_initialization(self):
        v = sigv4.AWSSigV4Verifier(
            "GET", "/", "", {}, "", "us-west-1", "ec2", {})
        return

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
