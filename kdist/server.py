#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from base64 import b64decode, b64encode
from boto.exception import BotoClientError, BotoServerError
import boto.kms
from flask import abort, Flask, make_response, request
from getopt import getopt, GetoptError
import hashlib
import hmac
from httplib import BAD_REQUEST, INTERNAL_SERVER_ERROR, UNAUTHORIZED
from json import dumps as json_dumps
from os import setegid, seteuid
from pwd import getpwnam
from six import string_types
from subprocess import PIPE, Popen
from sys import argv, stdout, stderr

_metadata = None
def get_instance_metadata():
    global _metadata
    if _metadata is None:
        import boto.utils
        _metadata = boto.utils.get_instance_metadata()
    return _metadata

def get_default_region():
    return get_instance_metadata()['placement']['availability-zone'][:-1]

class Handler(object):
    valid_signature_methods = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    max_request_size = 1 << 20
    default_path = (
        "/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/sbin:"
        "/opt/aws/bin")

    def __init__(self, app, key_id, region=None, encryption_context=None,
                 profile_name=None):
        super(Handler, self).__init__()
        if region is None: region = get_default_region()
        self.app = app
        self.key_id = key_id
        self.kms = boto.kms.connect_to_region(
            region, profile_name=profile_name)
        self.encryption_context = encryption_context
        self.server = None

        app.before_request(self.validate_message)
        app.add_url_rule("/exec", "exec", self.execute, methods=["PUT"])
        app.add_url_rule("/exit", "exit", self.exit, methods=["PUT"])
        return

    def validate_message(self):
        """
        Verify the message signature.  We use the AWS Sigv4 algorithm here.
        """
        headers = request.headers

        # Figure out how the client signed the request.
        sig_method = headers.get("SignatureMethod")
        sig_key_enc = headers.get("SignatureKeyEncrypted")
        sig = headers.get("Signature")

        # Make sure it's one we support.
        if (sig_method not in self.valid_signature_methods or
            sig_key_enc is None or
            sig is None):
            abort(BAD_REQUEST)

        try:
            sig_key = self.kms.decrypt(
                b64decode(sig_key_enc),
                encryption_context=self.encryption_context)
        except (BotoClientError, BotoServerError) as e:
            self.app.logger.error("Failed to decrypt signature key.",
                                  exc_info=True)
            abort(INTERNAL_SERVER_ERROR)

        # Refuse to verify requests larger than the maximum we're willing
        # to handle.
        data = request.stream.read(self.max_request_size + 1)
        if len(data) > self.max_request_size:
            abort(BAD_REQUEST)
        
        # Cache the data so we can decode it later on.
        request._cached_data = data

        # Run HMAC on the data; make sure the keys agree.
        self.app.logger.info("Key: %r", sig_key['Plaintext'])
        self.app.logger.info("Data: %r", data)
        mac = hmac.new(sig_key['Plaintext'], data,
                       digestmod=self.valid_signature_methods[sig_method])
        if sig.lower() != mac.hexdigest().lower():
            self.app.logger.warning("Invalid signature: expected %r, got %r",
                                    mac.hexdigest().lower(), sig.lower())
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
        response.headers["SignatureMethod"] = "sha256"

        data_key = self.kms.generate_data_key(
            self.key_id, encryption_context=self.encryption_context,
            key_spec="AES_256")
        response.headers["SignatureKeyEncrypted"] = b64encode(
            data_key["CiphertextBlob"])

        response.headers["Signature"] = hmac.new(
            data_key["Plaintext"], data, hashlib.sha256).hexdigest()

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
            not all([isinstance(arg, string_types) for arg in cmdline])):
            self.app.logger.warning("execute: invalid command line: %r",
                                    cmdline)
            abort(BAD_REQUEST)

        if (not isinstance(env, dict) or
            not all([(isinstance(key, string_types) and
                      isinstance(value, string_types))
                     for key, value in env.iteritems])):
            self.app.logger.warning("execute: invalid environment: %r", args)
            abort(BAD_REQUEST)

        if user is not None and not isinstance(user, string_types):
            self.app.logger.warning("execute: invalid user: %r", user)
            abort(BAD_REQUEST)

        if pwd is not None and not isinstance(pwd, string_types):
            self.app.logger.warning("execute: invalid directory: %r", pwd)
            abort(BAD_REQUEST)

        if not isinstance(stdin, string_types):
            self.app.logger.warning("execute: invalid stdin: %r", stdin)
            abort(BAD_REQUET)

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
            if uid != 0: seteuid(uid)
            if gid != 0: setegid(gid)

            proc = Popen(cmdline, stdin=PIPE, stdout=PIPE, stderr=PIPE,
                         close_fds=True, shell=False, cwd=pwd, env=env)
            out, err = proc.communicate(stdin)

            return self.create_response({
                'returncode': proc.returncode,
                'stdout': out,
                'stderr': err})
        finally:
            seteuid(0)
            setegid(0)

    def exit(self):
        self.server.shutdown_signal = True
        return self.create_response({"exiting": True})

def run_server():
    default_encryption_context = object()
    credential_store = None
    key_id = None
    port = 80
    region = None
    profile_name = None
    encryption_context = default_encryption_context

    try:
        opts, args = getopt(
            argv[1:], "C:e:hk:p:P:r:",
            ["credential-store=", "encryption-context=", "help", "key-id=",
             "port=", "profile=", "region="])
    except GetoptError as e:
        print(str(e), file=stderr)
        server_usage()
        return 1

    for opt, value in opts:
        if opt in ("-C", "--credential-store"):
            credential_store = value
        elif opt in ("-e", "--encryption-context"):
            try:
                k, v = value.split(":", 1)
            except:
                print("Invalid value for --encryption-context (expected 'key: "
                      "value'): %r" % value, file=stderr)
                server_usage()
                return 1

            if encryption_context is default_encryption_context:
                encryption_context = {}
            encryption_context[k.strip()] = v.strip()
        elif opt in ("-h", "--help"):
            server_usage(stdout)
            return 0
        elif opt in ("-k", "--key-id"):
            key_id = value
        elif opt in ("-P", "--port"):
            try:
                port = int(value)
                if not (0 < port < 65536):
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
    
    if len(args) > 0:
        print("Unknown argument %s" % args[0], file=stderr)
        server_usage()
        return 1

    if key_id is None:
        print("--key-id must be specified", file=stderr)
        server_usage()
        return 1

    if encryption_context is default_encryption_context:
        encryption_context = {"usage": "kdist"}

    app = Flask("kdist.server")
    handler = Handler(app, key_id, region=region, profile_name=profile_name,
                      encryption_context=encryption_context)

    from werkzeug.serving import make_server
    server = make_server("", port, app, threaded=True)
    handler.server = server
    server.serve_forever()

    return 0

def server_usage(fd=stderr):
    fd.write("""\
Usage: kdist-server [options]
Run the endpoint for handling build requests.

Options:
    -C <url> | --credential-store <url>
        Read credentials from the given URL.  Currently only S3 URLs in
        the form s3://<bucket>/<object> are supported.

        The credential store is a flat file encrypted with a KMS key.  Each
        line describes a single access key/secret key pair separated by
        whitespace.  Empty lines and comment lines starting with '#' are
        ignored.

        For example:
            # Credential store
            AKIDEXAMPLE1 wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
            AKIDEXAMPLE2 qHBl8ve/qpoFzk+0eN4ZxRYJlPDW8eEXAMPLEKEY

    -e <key>:<value> | --encryption-context <key>:<value>
        Set the encryption context for KMS encrypt and decrypt operations to
        the given name.  This may be specified multiple times.  The default
        is 'usage:kdist'.
    
    -h | --help
        Show this usage information.

    -k <id> | --key-id <id>
        Specify the key to use for signing responses.  This is required.

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
