#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from functools import partial
from glob import glob
import kdist.sigv4 as sigv4
from os.path import basename, dirname, splitext
from unittest import TestCase

region = "us-east-1"
service = "host"
key_mapping = { "AKIDEXAMPLE": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" }

class AWSSigV4TestCaseRunner(TestCase):
    def __init__(self, filebase, methodName="runTest"):
        super(AWSSigV4TestCaseRunner, self).__init__(methodName=methodName)
        self.filebase = filebase
        
    def runTest(self):
        with open(self.filebase + ".sreq", "r") as fd:
            method_line = fd.readline().strip()
            headers = {}

            while True:
                line = fd.readline()
                
                if line in ("\r\n", ""):
                    break

                self.assertTrue(line.endswith("\r\n"))
                header, value = line[:-2].split(":", 1)
                key = header.lower()
                value = value.strip()
                
                if key in headers:
                    headers[key].append(value)
                else:
                    headers[key] = [value]

            headers = dict([(key, ",".join(sorted(values)))
                            for key, values in headers.iteritems()])
            body = fd.read()

            first_space = method_line.find(" ")
            second_space = method_line.find(" ", first_space + 1)
            
            method = method_line[:first_space]
            uri_path = method_line[first_space + 1:second_space]

            qpos = uri_path.find("?")
            if qpos == -1:
                query_string = ""
            else:
                query_string = uri_path[qpos+1:]
                uri_path = uri_path[:qpos]

        with open(self.filebase + ".creq", "r") as fd:
            canonical_request = fd.read().replace("\r", "")

        with open(self.filebase + ".sts", "r") as fd:
            string_to_sign = fd.read().replace("\r", "")

        v = sigv4.AWSSigV4Verifier(
            method, uri_path, query_string, headers, body, region, service,
            key_mapping, None)

        self.assertEqual(
            v.canonical_request, canonical_request,
            "Canonical request mismatch in %s\nExpected: %r\nReceived: %r" %
            (self.filebase, canonical_request, v.canonical_request))
        self.assertEqual(
            v.string_to_sign, string_to_sign,
            "String to sign mismatch in %s\nExpected: %r\nReceived: %r" %
            (self.filebase, string_to_sign, v.string_to_sign))
        v.verify()
        return
    # end runTest

    def __str__(self):
        return "AWSSigV4TestCaseRunner: %s" % basename(self.filebase)
# end AWSSigV4TestCaseRunner

def get_test_cases():
    tests = []
    for filename in glob(dirname(__file__) + "/aws4_testsuite/*.req"):
        filebase = splitext(filename)[0]
        tests.append(AWSSigV4TestCaseRunner(filebase))

    return tests

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
