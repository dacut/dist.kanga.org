#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from kdist.s3 import S3ClientEncryptionHandler
from kdist.server import Server
from .testutils import find_open_port, InMemoryAWSServer
from threading import Thread
from unittest import TestCase

access_key = "access_key"
secret_key = "secret_key"
kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
region = "us-west-2"
keymap = {access_key: secret_key}

class ServerTest(TestCase):
    def test_s3_credentials(self):
        self.aws = InMemoryAWSServer(keymap, kms_key_id)
        self.aws.start()
        try:
            self.aws.buckets['credentials'] = {}

            s3 = boto.s3.connect_to_region(
                region, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key, is_secure=False,
                port=self.aws.port, host="127.0.0.1",
                calling_format=OrdinaryCallingFormat())
            kms = boto.kms.connect_to_region(
                region, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key, is_secure=False,
                port=self.aws.port, host="127.0.0.1")
            kms.auth_region_name = 'us-west-2'
            kms.auth_service_name = 'kms'

            key = s3.get_bucket("credentials").new_key("credentials.txt")
            enc = S3ClientEncryptionHandler(kms, kms_key_id)
            plaintext = ("# This is a comment followed by a blank line\n\n" +
                         "%s %s\n" % (access_key, secret_key))
            enc.write(key, plaintext)

            server = Server(
                "s3://credentials/credentials.txt", find_open_port(),
                region=region, kms_host="127.0.0.1", kms_port=self.aws.port,
                s3_host="127.0.0.1", s3_port=self.aws.port, s3_secure=False,
                kms_secure=False, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
            self.assertEqual(server.handler.keymap, keymap)
        finally:
            self.aws.stop()

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
