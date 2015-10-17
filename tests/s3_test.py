#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
from flask import abort, Flask, make_response, request
from hashlib import md5
from httplib import BAD_REQUEST, NOT_FOUND, OK, UNAUTHORIZED
from json import dumps as json_dumps, loads as json_loads
from kdist.sigv4 import AWSSigV4Verifier, InvalidSignatureError
from os import urandom
from os.path import dirname
from random import randint
from socket import AF_INET, error as SocketError, SOCK_STREAM, socket
from subprocess import Popen, PIPE
from sys import stderr
from threading import Thread
from tempfile import NamedTemporaryFile
from werkzeug.serving import make_server
from unittest import TestCase

port_range = (1024, 32767)

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

key_map = {"access_key": "secret_key"}

class InMemoryAWSServer(Thread):
    def __init__(self):
        super(InMemoryAWSServer, self).__init__()
        self.port = find_open_port()
        self.app = Flask("test.s3_test")
        self.app.add_url_rule("/", "s3", self.handle_request,
                              methods=["GET", "POST", "PUT"])
        self.app.add_url_rule("/<path:uri>", "s3", self.handle_request,
                              methods=["GET", "POST", "PUT"])
        self.server = make_server("", self.port, self.app)
        self.objects = {}
        self.headers = {}
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
        if request.method == "GET":
            data = self.objects.get(path)
            if data is None:
                abort(NOT_FOUND)

            headers = self.headers.get(path, {})
            return make_response(data, OK, headers)
        elif request.method in ("POST", "PUT"):
            data = request.get_data()
            self.objects[path] = data
            print("%s: path=%r data=%r" % (request.method, path, data))
            print(request.headers)
            self.headers[path] = {}

            for key, value in request.headers.iteritems():
                key = key.lower()
                
                if key == "content-type" or key.startswith("x-amz-meta-"):
                    self.headers[path][key] = value

            etag = md5(data).hexdigest()
            self.headers[path]["etag"] = etag
            
            return make_response("", OK, {"ETag": etag})
        else:
            abort(BAD_REQUEST)

class S3EncryptionTest(TestCase):
    def setUp(self):
        self.s3_server = InMemoryAWSServer()
        self.s3_server.start()
        return

    def tearDown(self):
        self.s3_server.stop()
        return
    
    def test_inmem_s3_server(self):
        self.java_encrypted_put("hello", "Hello world!")
        value = self.java_encrypted_get("hello")
        self.assertEqual(value, "Hello world!")
        return

    def java_encrypted_get(self, object_name):
        tmpfile = NamedTemporaryFile()
        kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
        args = " ".join([
            "--bucket hello --object " + object_name,
            "--kmsKeyId " + kms_key_id,
            "--intercept http://127.0.0.1:%s/" % self.s3_server.port,
            "--outputFile " + tmpfile.name,
            "--read"
        ])
        
        cwd=dirname(dirname(__file__)) + "/javacompat"
        print(cwd)
        proc = Popen(["mvn", "-e", "exec:java",
                      "-Dexec.mainClass=org.kanga.dist.S3Test",
                      "-Dexec.args=" + args], stdin=PIPE, cwd=cwd)

        proc.communicate()
        if proc.returncode != 0:
            raise ValueError("Get failed with exitcode %d" % proc.returncode)

        tmpfile.seek(0)
        data = tmpfile.read()

        print("Reading output from %s" % tmpfile.name)
        
        return data

    def java_encrypted_put(self, object_name, value):
        kms_key_id = "01234567-89ab-cdef-0123-456789abcdef"
        args = " ".join([
            "--bucket hello --object " + object_name,
            "--kmsKeyId " + kms_key_id,
            "--intercept http://127.0.0.1:%s/" % self.s3_server.port,
            "--write"
        ])
        
        cwd=dirname(dirname(__file__)) + "/javacompat"
        print(cwd)
        proc = Popen(["mvn", "-e", "exec:java",
                      "-Dexec.mainClass=org.kanga.dist.S3Test",
                      "-Dexec.args=" + args], stdin=PIPE, cwd=cwd)

        proc.communicate(value)
        if proc.returncode != 0:
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
