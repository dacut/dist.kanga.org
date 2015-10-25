#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from kdist.client import KDistConnection, KDistServerError
from kdist.s3 import S3ClientEncryptionHandler
from kdist.server import Server
from signal import SIGKILL
from six.moves import cStringIO
from .testutils import find_open_port, InMemoryAWSServer
from threading import Thread
from unittest import TestCase

access_key = "access_key"
secret_key = "secret_key"
kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
region = "us-west-2"
keymap = {access_key: secret_key}

class ServerTest(TestCase):
    def create_aws_server(self):
        self.aws = InMemoryAWSServer(keymap, kms_key_id)
        self.aws.start()
        self.aws.buckets['credentials'] = {}

    def connect_s3(self):
        self.s3 = boto.s3.connect_to_region(
            region, aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.aws.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())

    def connect_kms(self):
        self.kms = boto.kms.connect_to_region(
            region, aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.aws.port, host="127.0.0.1")
        self.kms.auth_region_name = 'us-west-2'
        self.kms.auth_service_name = 'kms'

    def create_credentials(self, keymap):
        plaintext = cStringIO()
        plaintext.write("# This is a comment followed by a blank line\n\n")

        for item in keymap.iteritems():
            plaintext.write("%s %s\n" % item)

        plaintext = plaintext.getvalue()

        key = self.s3.get_bucket("credentials").new_key("credentials.txt")
        enc = S3ClientEncryptionHandler(self.kms, kms_key_id)
        enc.write(key, plaintext)
        return

    def test_s3_credentials(self):
        self.create_aws_server()
        try:
            self.connect_s3()
            self.connect_kms()
            self.create_credentials(keymap)

            server = Server(
                "s3://credentials/credentials.txt", find_open_port(),
                region=region, kms_host="127.0.0.1", kms_port=self.aws.port,
                s3_host="127.0.0.1", s3_port=self.aws.port, s3_secure=False,
                kms_secure=False, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
            self.assertEqual(server.handler.keymap, keymap)
        finally:
            self.aws.stop()

    def test_exec_ok(self):
        self.create_aws_server()
        server_pid = -1

        try:
            self.connect_s3()
            self.connect_kms()
            self.create_credentials(keymap)

            port = find_open_port()
            server = Server(
                "s3://credentials/credentials.txt", port, region=region,
                kms_host="127.0.0.1", kms_port=self.aws.port,
                s3_host="127.0.0.1", s3_port=self.aws.port, s3_secure=False,
                kms_secure=False, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
            server_runner = Thread(target=server.run)
            server_runner.start()

            try:
                # Send a request
                client = KDistConnection(
                    host="127.0.0.1", port=port, is_secure=False,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key)
                client.auth_region_name = region
                client.auth_service_name = "kdist"
                result = client.execute(
                    command=["/bin/pwd"], directory="/")
                self.assertEqual(result['returncode'], 0)
                self.assertEqual(result['stdout'], "/\n")
                self.assertEqual(result['stderr'], "")

                result = client.execute(
                    command=["/does/not/exist"], directory="/")
                self.assertEqual(result['returncode'], 127)
            finally:
                server.handler.server.shutdown()
                server_runner.join()
        finally:
            self.aws.stop()
            if server_pid != -1:
                kill(server_pid, SIGKILL)

    def test_bad_params(self):
        self.create_aws_server()
        server_pid = -1

        try:
            self.connect_s3()
            self.connect_kms()
            self.create_credentials(keymap)

            port = find_open_port()
            server = Server(
                "s3://credentials/credentials.txt", port, region=region,
                kms_host="127.0.0.1", kms_port=self.aws.port,
                s3_host="127.0.0.1", s3_port=self.aws.port, s3_secure=False,
                kms_secure=False, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
            server_runner = Thread(target=server.run)
            server_runner.start()

            try:
                # Send a request
                client = KDistConnection(
                    host="127.0.0.1", port=port, is_secure=False,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key)
                client.auth_region_name = region
                client.auth_service_name = "kdist"

                for cmd in [[], "asdf", [{"x": "y"}]]:
                    try:
                        result = client.execute(command=cmd, directory="/")
                        self.fail("Expected KDistServerError")
                    except KDistServerError:
                        pass

                for env in [["foo"], "", {"x": []}, {"": "x"}]:
                    try:
                        result = client.execute(
                            command=["/bin/pwd"], directory="/",
                            environment=env)
                        self.fail("Expected KDistServerError: env=%r" % env)
                    except KDistServerError:
                        pass

                for user in [7, ["root"], "this-user-does-not-exist"]:
                    try:
                        result = client.execute(
                            command=["/bin/pwd"], directory="/", user=user)
                        self.fail("Expected KDistServerError")
                    except KDistServerError:
                        pass

                for dir in [7, ["/"], {"1": "2"}]:
                    try:
                        result = client.execute(
                            command=["/bin/pwd"], directory=dir)
                        self.fail("Expected KDistServerError")
                    except KDistServerError:
                        pass

                for stdin in [10, [], {"1": "2"}]:
                    try:
                        result = client.execute(
                            command=["/bin/pwd"], directory="/", stdin=stdin)
                        self.fail("Expected KDistServerError")
                    except KDistServerError:
                        pass
                    
            finally:
                server.handler.server.shutdown()
                server_runner.join()
        finally:
            self.aws.stop()
            if server_pid != -1:
                kill(server_pid, SIGKILL)

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
