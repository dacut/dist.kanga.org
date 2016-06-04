#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.utils
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from flask import abort, Flask, make_response, request
from getopt import getopt, GetoptError
import hashlib
from httplib import BAD_REQUEST, UNAUTHORIZED
from json import dumps as json_dumps
from kdist.s3 import S3ClientEncryptionHandler
from kdist.sigv4 import AWSSigV4Verifier, InvalidSignatureError
from os import setegid, seteuid
from pwd import getpwnam
from six import string_types
from six.moves import cStringIO
from subprocess import PIPE, Popen
from sys import argv, stdout, stderr

_metadata = None
def get_instance_metadata(): # pragma: no cover
    global _metadata
    if _metadata is None:
        _metadata = boto.utils.get_instance_metadata()
    return _metadata

def get_default_region(): # pragma: no cover
    return get_instance_metadata()['placement']['availability-zone'][:-1]

class Handler(object):
    max_request_size = 1 << 20
    default_path = (
        "/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/sbin:"
        "/opt/aws/bin")

    service = "kdist"

    def __init__(self, app, region, service=None, keymap=None):
        super(Handler, self).__init__()
        self.app = app
        self.region = region
        self.service = service
        self.keymap = keymap if keymap is not None else {}
        self.server = None

        app.before_request(self.validate_message)
        app.add_url_rule("/exec", "exec", self.execute, methods=["POST"])
        app.add_url_rule("/exit", "exit", self.exit, methods=["POST"])
        return

    def validate_message(self):
        """
        Verify the message signature.  We use the AWS Sigv4 algorithm here.
        """

        # Refuse to verify requests larger than the maximum we're willing
        # to handle.
        body = request.stream.read(self.max_request_size + 1)
        if len(body) > self.max_request_size:
            abort(BAD_REQUEST)

        # Cache the body so we can decode it later on.
        request._cached_data = body

        # Verify the signature.
        verifier = AWSSigV4Verifier(
            request.method, request.path, request.query_string,
            request.headers, body, self.region, self.service, self.keymap)

        try:
            verifier.verify()
        except InvalidSignatureError:
            from traceback import print_exc
            print_exc()
            abort(UNAUTHORIZED)

        # We only accept JSON; force it to be parsed now.
        try:
            request.get_json()
        except:
            self.app.logger.warning("No JSON data available", exc_info=True)
            raise

        return

    def create_response(self, data):
        if not isinstance(data, string_types):
            data = json_dumps(data)

        response = make_response(data)
        response.headers["Content-Type"] = "application/json"
        response.headers["ETag"] = '"' + hashlib.sha256(data).hexdigest() + '"'

        return response

    def execute(self):
        data = request.get_json()
        if not isinstance(data, dict):
            self.app.logger.warning("execute: invalid JSON data: %r", data)
            abort(BAD_REQUEST)

        cmdline = data.get("command")
        env = data.get("environment", {})
        user = data.get("user", None)
        pwd = data.get("directory", None)
        stdin = data.get("stdin", "")

        if (not isinstance(cmdline, (list, tuple)) or
                len(cmdline) == 0 or
                not all([isinstance(arg, string_types) for arg in cmdline])):
            self.app.logger.warning("execute: invalid command line: %r",
                                    cmdline)
            abort(BAD_REQUEST)

        if (not isinstance(env, dict) or
                not all([(isinstance(key, string_types) and
                          isinstance(value, string_types) and
                          len(key) > 0)
                         for key, value in env.iteritems()])):
            self.app.logger.warning("execute: invalid environment: %r", env)
            abort(BAD_REQUEST)

        if user is not None and not isinstance(user, string_types):
            self.app.logger.warning("execute: invalid user: %r", user)
            abort(BAD_REQUEST)

        if pwd is not None and not isinstance(pwd, string_types):
            self.app.logger.warning("execute: invalid directory: %r", pwd)
            abort(BAD_REQUEST)

        if not isinstance(stdin, string_types):
            self.app.logger.warning("execute: invalid stdin: %r", stdin)
            abort(BAD_REQUEST)

        user = "root" if user is None else user

        try:
            pwent = getpwnam(user)
            default_home = pwent.pw_dir
            uid = pwent.pw_uid
            gid = pwent.pw_gid
        except KeyError:
            self.app.logger.warning("execute: unknown user: %r", user)
            abort(BAD_REQUEST)

        if pwd is None:
            pwd = default_home

        env.setdefault("HOME", default_home)
        env.setdefault("LOGNAME", user)
        env.setdefault("USER", user)
        env.setdefault("PATH", self.default_path)
        env.setdefault("PWD", pwd)
        env.setdefault("SHLVL", "1")

        try:
            if uid != 0:
                seteuid(uid)
            if gid != 0:
                setegid(gid)

            proc = Popen(cmdline, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                         close_fds=True, shell=False, cwd=pwd, env=env)
            out, err = proc.communicate(stdin)

            return self.create_response({
                'returncode': proc.returncode,
                'stdout': out,
                'stderr': err})
        except OSError as e:
            return self.create_response({
                'returncode': 127,
                'stdout': "",
                'stderr': str(e)})
        finally:
            try:
                seteuid(0)
                setegid(0)
            except OSError as e: # When running in test mode
                pass

    def exit(self):
        self.server.shutdown_signal = True
        return self.create_response({"exiting": True})

class Server(object):
    def __init__(self, credential_store, port, region, profile_name=None,
                 kms_host=None, kms_port=None, s3_host=None, s3_port=None,
                 s3_secure=True, kms_secure=True, aws_access_key_id=None,
                 aws_secret_access_key=None):
        from werkzeug.serving import make_server

        super(Server, self).__init__()
        self.port = port

        if credential_store.startswith("s3://"):
            kms = boto.kms.connect_to_region(
                region, profile_name=profile_name, host=kms_host,
                port=kms_port, is_secure=kms_secure,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key)
            kms.auth_region_name = region
            kms.auth_service_name = "kms"

            s3 = boto.s3.connect_to_region(
                region, profile_name=profile_name,
                calling_format=OrdinaryCallingFormat(), host=s3_host,
                port=s3_port, is_secure=s3_secure,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key)

            self.read_credentials_from_s3(credential_store, kms, s3)
        else:
            self.read_credentials_from_file(credential_store)

        self.app = Flask("kdist.server")
        self.handler = Handler(self.app, region, keymap=self.credentials)
        self.handler.server = make_server(
            "", self.port, self.app, threaded=True)
        self.credentials = None
        return

    def run(self):
        self.handler.server.serve_forever()

    def read_credentials_from_s3(self, s3_url, kms, s3):
        """
        read_credentials_from_s3(s3_url, kms, s3) -> dict

        Read access-key/secret-key map from the specified S3 URL (in the form
        s3://bucket/key).
        """
        assert s3_url.startswith("s3://")
        try:
            bucket_name, key_name = s3_url[5:].split("/", 1)
        except:
            raise ValueError("Invalid S3 URL: %s" % s3_url)

        enc = S3ClientEncryptionHandler(kms)
        bucket = s3.get_bucket(bucket_name)
        key = bucket.get_key(key_name)

        data = enc.read(key)
        self.read_credentials_from_stream(cStringIO(data))

    def read_credentials_from_file(self, filename):
        with open(filename, "r") as fd:
            self.read_credentials_from_stream(fd)

    def read_credentials_from_stream(self, fd):
        self.credentials = {}

        for line in fd:
            line = line.strip()
            if line.startswith("#") or len(line) == 0:
                continue

            access_key, secret_key = line.split()
            self.credentials[access_key] = secret_key

def run_server(args=None): # pragma: no cover
    credential_store = None
    port = 80
    profile_name = None
    region = None

    if args is None:
        args = argv[1:]

    try:
        opts, args = getopt(
            args, "C:hp:P:r:",
            ["credential-store=", "help", "port=", "profile=", "region="])
    except GetoptError as e:
        print(str(e), file=stderr)
        server_usage()
        return 1

    for opt, value in opts:
        if opt in ("-C", "--credential-store"):
            credential_store = value
        elif opt in ("-h", "--help"):
            server_usage(stdout)
            return 0
        elif opt in ("-P", "--port"):
            try:
                port = int(value)
                if not 0 < port < 65536:
                    raise ValueError()
            except ValueError:
                print("Invalid port value %s" % value, file=stderr)
                server_usage()
                return 1
        elif opt in ("-p", "--profile"):
            profile_name = value
        elif opt in ("-r", "--region"):
            region = value
        else:
            print("Unknown option %s" % opt, file=stderr)
            server_usage()
            return 1

    if credential_store is None:
        print("--credential-store must be specified", file=stderr)
        server_usage()
        return 1

    if len(args) > 0:
        print("Unknown argument %s" % args[0], file=stderr)
        server_usage()
        return 1

    server = Server(credential_store, port=port, profile_name=profile_name,
                    region=region)
    server.run()
    return 0

def server_usage(fd=stderr): # pragma: no cover
    fd.write("""\
Usage: kdist-server [options]
Run the endpoint for handling build requests.

Options:
    -C <url> | --credential-store <url>
        Read credentials from the given URL.  This can be an S3 URLs in
        the form s3://<bucket>/<object> or a filename.

        The credential store is a flat file (encrypted with a KMS key if
        stored in S3).  Each line describes a single access key/secret key
        pair separated by whitespace.  Empty lines and comment lines starting
        with '#' are ignored.

        For example:
            # Credential store
            AKIDEXAMPLE1 wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
            AKIDEXAMPLE2 qHBl8ve/qpoFzk+0eN4ZxRYJlPDW8eEXAMPLEKEY

    -h | --help
        Show this usage information.

    -P <num> | --port <num>
        Specify the port to listen on.  Defaults to 80.

    -p <name> | --profile <name>
        Use the specified profile for AWS credentials.

    -r <name> | --region <name>
        Sets the AWS region to use for making KMS requests.  Defaults to the
        region this host is in.
""")
    fd.flush()
    return

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
