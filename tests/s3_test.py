#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from flask import abort, Flask, make_response, request
from hashlib import md5
from httplib import BAD_REQUEST, NOT_FOUND, OK, UNAUTHORIZED
from json import dumps as json_dumps, loads as json_loads
from kdist.s3 import S3ClientEncryptionHandler
from kdist.sigv4 import AWSSigV4Verifier, InvalidSignatureError
from logging import basicConfig, DEBUG
from math import modf
from os import urandom
from os.path import dirname
from random import randint
from six.moves import cStringIO
from socket import AF_INET, error as SocketError, SOCK_STREAM, socket
from string import ascii_letters, digits, punctuation
from subprocess import Popen, PIPE
from sys import stderr, stdout
from threading import Thread
from time import gmtime, strftime, time
from tempfile import NamedTemporaryFile
from werkzeug.serving import make_server
from unittest import TestCase

port_range = (1024, 32767)
access_key = "access_key"
secret_key = "secret_key"
kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
key_map = {access_key: secret_key}
s3_owner = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
s3_display_name = 's3test'

basicConfig(level=DEBUG)

def find_open_port():
    """
    Look for an open port on the loopback interface.
    """
    while True:
        port = randint(*port_range)
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except SocketError:
            pass

class InMemoryS3Object(object):
    def __init__(self, data=None, headers=None, last_modified=None):
        super(InMemoryS3Object, self).__init__()
        self.data = data
        self.headers = headers
        self.last_modified = last_modified if last_modified else time()
        return

class InMemoryAWSServer(Thread):
    def __init__(self):
        super(InMemoryAWSServer, self).__init__()
        self.port = find_open_port()
        self.app = Flask("test.s3_test")
        self.app.add_url_rule("/", "s3", self.handle_request,
                              methods=["HEAD", "GET", "POST", "PUT"])
        self.app.add_url_rule("/<path:uri>", "s3", self.handle_request,
                              methods=["HEAD", "GET", "POST", "PUT"])
        self.server = make_server("", self.port, self.app)
        self.buckets = {}
        return

    def run(self):
        self.server.serve_forever()
        return

    def stop(self):
        self.server.shutdown()
        self.join()
        return

    def handle_request(self, *args, **kw):
        target = request.headers.get("X-Amz-Target", "")
        if target.startswith("TrentService."):
            return self.handle_trent_request()
        else:
            return self.handle_s3_request()

    def handle_trent_request(self):
        target = request.headers.get("X-Amz-Target")
        data = request.get_data()
        verifier = AWSSigV4Verifier(
            request_method=request.method, uri_path=request.path,
            query_string=request.query_string, headers=request.headers,
            body=data, region="us-west-2", service="kms",
            key_mapping=key_map)
        try:
            verifier.verify()
        except InvalidSignatureError as e:
            print(str(e), file=stderr)
            return make_response(json_dumps(
                {"__type": "AuthFailure",
                 "message": "Invalid signature"}), UNAUTHORIZED)

        try:
            params = json_loads(data)
        except ValueError as e:
            return make_response(json_dumps(
                {"__type": "MalformedQueryString",
                 "message": "Could not decode JSON data"}), BAD_REQUEST)

        if target == "TrentService.GenerateDataKey":
            return self.handle_trent_generate_data_key_request(params)
        elif target == "TrentService.Decrypt":
            return self.handle_trent_decrypt_request(params)

        print("Unknown action %s: params=%r" % (target, params), file=stderr)
        
        return make_response(json_dumps(
            {"__type": "InvalidAction",
             "message": "Unknown action %s" % target}), BAD_REQUEST)

    def handle_trent_decrypt_request(self, params):
        try:
            ciphertext_blob = params["CiphertextBlob"]
            encryption_context = params.get("EncryptionContext", {})
        except KeyError as e:
            return make_response(json_dumps(
                {"__type": "MissingParameter",
                 "message": "Missing parameter: %s" % e.args[0]}), BAD_REQUEST)

        encrypt_params = json_loads(b64decode(ciphertext_blob))
        key_id = encrypt_params["KeyId"]
        encryption_context = encrypt_params["EncryptionContext"]
        plaintext = encrypt_params["Plaintext"]

        # Plaintext is already base64 encoded.

        return make_response(json_dumps(
            {"KeyId": key_id, "Plaintext": plaintext}), OK)


    def handle_trent_generate_data_key_request(self, params):
        try:
            key_id = params["KeyId"]
            context = params.get("EncryptionContext", {})
            key_spec = params.get("KeySpec", "AES_256")
        except KeyError as e:
            return make_response(json_dumps(
                {"__type": "MissingParameter",
                 "message": "Missing parameter: %s" % e.args[0]}), BAD_REQUEST)

        # Random key
        if key_spec == "AES_256":
            plaintext = urandom(32)
        elif key_spec == "AES_128":
            plaintext = urandom(16)
        else:
            return make_response(json_dumps(
                {"__type": "InvalidParameter",
                 "message": "Invalid KeySpec %r" % key_spec}), BAD_REQUEST)

        ciphertext_blob = b64encode(json_dumps(
            {"KeyId": key_id,
             "EncryptionContext": context,
             "Plaintext": b64encode(plaintext)}))

        return make_response(json_dumps(
            {'KeyId': key_id,
             'CiphertextBlob': ciphertext_blob,
             'Plaintext': b64encode(plaintext)}))

    def handle_s3_request(self):
        path = request.environ["PATH_INFO"]
        parts = path[1:].split("/", 1)
        bucket_name = parts[0]
        object_name = parts[1] if len(parts) > 0 else None

        bucket = self.buckets.get(bucket_name)
        if bucket is None:
            abort(NOT_FOUND)
        
        if request.method in ("GET", "HEAD"):
            if not object_name:
                return self.handle_s3_list_bucket(bucket)
            else:
                obj = bucket.get(object_name)
                if obj is None:
                    abort(NOT_FOUND)
                return self.handle_s3_get_object(obj)
        elif request.method in ("POST", "PUT"):
            if not object_name:
                abort(BAD_REQUEST)
            return self.handle_s3_put_object(bucket, object_name)
        else:
            abort(BAD_REQUEST)

    def handle_s3_list_bucket(self, bucket):
        # List bucket
        if request.method == "HEAD":
            # Don't do anything.
            return make_response("", OK)

        result = cStringIO()
        result.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        result.write(
            '<ListBucketResult '
            'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">')
        result.write('<Name>')
        result.write(bucket_name)
        result.write('</Name>')
        result.write('<Prefix></Prefix>')
        result.write('<Marker></Marker>')
        result.write('<MaxKeys>%d</MaxKeys>' % max(1000, len(bucket)))
        result.write('<IsTruncated>false</IsTruncated>')

        for key, obj in bucket.iteritems():
            result.write('<Contents>')
            result.write('<Key>%s</Key>' % key)
            result.write('<LastModified>%s</LastModified>' %
                         strftime("%Y-%m-%dT%H:%M:%S",
                                  gmtime(key.last_modified)) +
                         ".%03fZ" % 1000 * modf(key.last_modified)[0])
            result.write('<ETag>&quot;' + key.headers['etag'] + '&quot;</ETag>')
            result.write('<Size>%d</Size>' % len(key.data))
            result.write('<Owner><ID>%s</ID>' % s3_owner)
            result.write('<DisplayName>%s</DisplayName></Owner>' %
                         s3_display_name)
            result.write('<StorageClass>STANDARD</Storage>')
            result.write('</Contents>')

        result.write('</ListBucketResultSet>\n')
        result = result.getvalue()
        etag = md5(result).hexdigest()

        return make_response(result, OK, {'ETag': etag})

    def handle_s3_get_object(self, obj):
        headers = dict(obj.headers)
        if 'etag' in headers:
            del headers['etag']
        if 'content-length' in headers:
            del headers['content-length']
            
        headers['Last-Modified'] = strftime(
            "%a, %d %b %Y %H:%M:%S GMT", gmtime(obj.last_modified))
        headers['ETag'] = md5(obj.data).hexdigest()

        data = obj.data if request.method == "GET" else ""
        headers['Content-Length'] = str(len(obj.data))

        return make_response(data, OK, headers)

    def handle_s3_put_object(self, bucket, object_name):
        data = request.get_data()

        headers = {}
        for key, value in request.headers.iteritems():
            key = key.lower()

            if key == "content-type" or key.startswith("x-amz-meta-"):
                headers[key] = value

        bucket[object_name] = InMemoryS3Object(data, headers)
        etag = md5(data).hexdigest()
        return make_response("", OK, {"ETag": '"' + etag + '"'})
    
class S3EncryptionTest(TestCase):
    def setUp(self):
        self.s3_server = InMemoryAWSServer()
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
        enc.write(key, "Hello world!")

        result = self.java_encrypted_get("hello")
        self.assertEqual(result, "Hello world!")
        return

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

        print("Reading output from %s" % tmpfile.name)
        
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
