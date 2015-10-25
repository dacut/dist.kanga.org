#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from kdist.s3 import S3ClientEncryptionHandler, EncryptionError
from os.path import dirname
from string import ascii_letters, digits, punctuation
from subprocess import Popen, PIPE
from sys import stderr, stdout
from tempfile import NamedTemporaryFile
from unittest import TestCase
from .testutils import InMemoryAWSServer

access_key = "access_key"
secret_key = "secret_key"
kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
keymap = {access_key: secret_key}

class S3EncryptionTest(TestCase):
    def setUp(self):
        self.s3_server = InMemoryAWSServer(keymap, kms_key_id)
        self.s3_server.start()
        self.s3_server.buckets['hello'] = {}
        return

    def tearDown(self):
        self.s3_server.stop()
        return
    
    def test_inmem_s3_server(self):
        self.java_encrypted_put("hello", "Hello world!")
        value = self.java_encrypted_get("hello")
        self.assertEqual(value, "Hello world!")
        return

    def test_java_write_python_read(self):
        plaintext = (ascii_letters + digits + punctuation) * 50
        self.java_encrypted_put("mytestkey", plaintext)

        kms = boto.kms.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1")
        kms.auth_region_name = 'us-west-2'
        kms.auth_service_name = 'kms'
        
        s3 = boto.s3.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())
        enc = S3ClientEncryptionHandler(kms, kms_key_id)
        bucket = s3.get_bucket("hello")
        key = bucket.new_key("mytestkey")
        result = enc.read(key)

        self.assertEqual(plaintext, result)
        return

    def test_python_write_java_read(self):
        kms = boto.kms.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1")
        kms.auth_region_name = 'us-west-2'
        kms.auth_service_name = 'kms'
        
        s3 = boto.s3.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())
        enc = S3ClientEncryptionHandler(kms, kms_key_id)

        bucket = s3.get_bucket("hello")
        key = bucket.new_key("hello")
        enc.write(key, "Hello world!", headers={"content-type": "text/plain"})

        result = self.java_encrypted_get("hello")
        self.assertEqual(result, "Hello world!")
        return

    def test_missing_metadata(self):
        kms = boto.kms.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1")
        kms.auth_region_name = 'us-west-2'
        kms.auth_service_name = 'kms'
        
        s3 = boto.s3.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())
        enc = S3ClientEncryptionHandler(kms, kms_key_id)

        bucket = s3.get_bucket("hello")
        key = bucket.new_key("missing_metadata")        
        enc.write(key, "Hello world!")
        del key

        # Remove bits of metadata.
        obj = self.s3_server.buckets["hello"]["missing_metadata"]
        for header in ['x-amz-meta-x-amz-key-v2', 'x-amz-meta-x-amz-wrap-alg',
                       'x-amz-meta-x-amz-cek-alg', 'x-amz-meta-x-amz-iv',
                       'x-amz-meta-x-amz-matdesc']:
            value = obj.headers[header]
            del obj.headers[header]

            # Make sure we get an EncryptionError
            try:
                key = bucket.new_key("missing_metadata")
                enc.read(key)
                self.fail("Exepcted EncryptionError for missing header %s" %
                          header)
            except EncryptionError:
                del key

            obj.headers[header] = value

        # Corrupt the data key
        dk = obj.headers['x-amz-meta-x-amz-key-v2']
        obj.headers['x-amz-meta-x-amz-key-v2'] = "aa"
        try:
            key = bucket.new_key("missing_metadata")
            enc.read(key)
            self.fail("Expected EncryptionError for corrupted header "
                      "x-amz-meta-x-amz-key-v2")
        except EncryptionError as e:
            del key
        obj.headers['x-amz-meta-x-amz-key-v2'] = dk

        # Corrupt the material description
        md = obj.headers['x-amz-meta-x-amz-matdesc']
        obj.headers['x-amz-meta-x-amz-matdesc'] = "aa"
        try:
            key = bucket.new_key("missing_metadata")
            enc.read(key)
            self.fail("Expected EncryptionError for corrupted header "
                      "x-amz-meta-x-amz-matdesc")
        except EncryptionError as e:
            del key
        obj.headers['x-amz-meta-x-amz-matdesc'] = md

        # Remvoe critical JSON from the matdesc.
        md = obj.headers['x-amz-meta-x-amz-matdesc']
        obj.headers['x-amz-meta-x-amz-matdesc'] = '{}'
        try:
            key = bucket.new_key("missing_metadata")
            enc.read(key)
            self.fail("Expected EncryptionError for corrupted header "
                      "x-amz-meta-x-amz-matdesc")
        except EncryptionError as e:
            del key
        obj.headers['x-amz-meta-x-amz-matdesc'] = md
        
        return

    def test_bad_algorithms(self):
        kms = boto.kms.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1")
        kms.auth_region_name = 'us-west-2'
        kms.auth_service_name = 'kms'
        
        s3 = boto.s3.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())
        enc = S3ClientEncryptionHandler(kms, kms_key_id)

        bucket = s3.get_bucket("hello")
        key = bucket.new_key("bad_algorithms")

        try:
            enc.write(key, "Hello world!", wrapper_algorithm="foo")
            self.fail("Expected EncryptionError")
        except EncryptionError:
            pass

        try:
            enc.write(key, "Hello world!", encryption_algorithm="foo")
            self.fail("Expected EncryptionError")
        except EncryptionError:
            pass

    def test_unknown_key(self):
        kms = boto.kms.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1")
        kms.auth_region_name = 'us-west-2'
        kms.auth_service_name = 'kms'
        
        s3 = boto.s3.connect_to_region(
            "us-west-2", aws_access_key_id=access_key,
            aws_secret_access_key=secret_key, is_secure=False,
            port=self.s3_server.port, host="127.0.0.1",
            calling_format=OrdinaryCallingFormat())
        enc = S3ClientEncryptionHandler(kms, "foo")

        bucket = s3.get_bucket("hello")
        key = bucket.new_key("unknown_key")
        try:
            enc.write(key, "Hello world!")
            self.fail("Expected EncryptionError")
        except EncryptionError:
            pass
                                 
    def java_encrypted_get(self, object_name):
        tmpfile = NamedTemporaryFile()
        args = " ".join([
            "--bucket hello --object " + object_name,
            "--kmsKeyId " + kms_key_id,
            "--intercept http://127.0.0.1:%s/" % self.s3_server.port,
            "--outputFile " + tmpfile.name,
            "--read"
        ])
        
        cwd=dirname(dirname(__file__)) + "/javacompat"
        proc = Popen(["mvn", "-e", "exec:java",
                      "-Dexec.mainClass=org.kanga.dist.S3Test",
                      "-Dexec.args=" + args],
                     stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=cwd)

        out, err = proc.communicate()
        if proc.returncode != 0:
            stdout.write(out)
            stderr.write(err)
            stdout.flush()
            stderr.flush()
            raise ValueError("Get failed with exitcode %d" % proc.returncode)

        tmpfile.seek(0)
        data = tmpfile.read()
        return data

    def java_encrypted_put(self, object_name, value):
        args = " ".join([
            "--bucket hello --object " + object_name,
            "--kmsKeyId " + kms_key_id,
            "--intercept http://127.0.0.1:%s/" % self.s3_server.port,
            "--write"
        ])
        
        cwd=dirname(dirname(__file__)) + "/javacompat"
        proc = Popen(["mvn", "-e", "exec:java",
                      "-Dexec.mainClass=org.kanga.dist.S3Test",
                      "-Dexec.args=" + args],
                     stdin=PIPE, stdout=PIPE, stderr=PIPE, cwd=cwd)

        out, err = proc.communicate(value)
        if proc.returncode != 0:
            stdout.write(out)
            stderr.write(err)
            stdout.flush()
            stderr.flush()
            raise ValueError("Put failed with exitcode %d" % proc.returncode)

        return

"""
mvn -e exec:java -Dexec.mainClass="org.kanga.dist.S3Test" -Dexec.args="--bucket hello --object foo --kmsKeyId 01234567-89ab-cdef-0123-456789abcdef --intercept http://127.0.0.1:57000"
"""

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
