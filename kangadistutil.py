from __future__ import absolute_import, print_function
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
import boto.sts
from logging import (
    DEBUG, FileHandler, Formatter, getLogger, Handler, INFO, StreamHandler)
from logging.handlers import SysLogHandler
from os import getenv
from os.path import basename, exists
from re import compile as re_compile
from subprocess import PIPE, Popen
from sys import argv, stderr
from syslog import LOG_LOCAL1
from time import strftime

id_regex = re_compile(r'^\s*ID=(?:"([^"]*)"|([^ ]*))\s*$')
version_regex = re_compile(r'^\s*VERSION=(?:"([^"]*)"|([^ ]*))\s*$')
linux_dist = None
dist_version = None
log = None

def get_os_version():
    """
    get_os_version() -> (str, str)

    Return the Linux distribution and version as a pair of strings.
    """
    global linux_dist, dist_version

    if linux_dist is None or dist_version is None:
        if not exists("/etc/os-release"):
            raise ValueError("File /etc/os-release not found")

        with open("/etc/os-release", "r") as fd:
            for line in fd:
                m = id_regex.match(line)
                if m:
                    if m.group(1):
                        linux_dist = m.group(1)
                    else:
                        linux_dist = m.group(2)

                m = version_regex.match(line)
                if m:
                    if m.group(1):
                        dist_version = m.group(1)
                    else:
                        dist_version = m.group(2)

        if not linux_dist:
            raise ValueError("Failed to find ID=... line in /etc/os-release")

        if not dist_version:
            raise ValueError("Failed to find VERSION=... line in "
                             "/etc/os-release")

    return (linux_dist, dist_version)

class MultiHandler(Handler):
    """
    Send log events to multiple handlers.
    """
    def __init__(self, handlers):
        super(MultiHandler, self).__init__()
        self.handlers = handlers
        return

    def emit(self, record):
        for handler in self.handlers:
            handler.emit(record)
        return

    def flush(self):
        for handler in self.handlers:
            handler.flush()

class Log8601Formatter(Formatter):
    def formatTime(self, record, datefmt=None):
        return "%s.%03d" % (
            strftime("%Y-%m-%dT%H:%M:%S", self.converter(record.created)),
            int(record.msecs * 1000))

def setup_logging():
    global log

    progname = basename(argv[0])
    log = getLogger()
    log.setLevel(DEBUG)
    stderr_handler = StreamHandler(stderr)
    syslog_handler = SysLogHandler(address="/dev/log", facility=LOG_LOCAL1)
    buildlog_handler = FileHandler(getenv("HOME") + "/build.log")
    stderr_handler.setFormatter(
        Log8601Formatter("%(asctime)s %(levelname)s: %(message)s"))
    syslog_handler.setFormatter(
        Log8601Formatter(progname + " %(asctime)s %(levelname)s: %(message)s"))
    buildlog_handler.setFormatter(
        Log8601Formatter(progname + " %(asctime)s %(levelname)s: %(message)s"))
    log.addHandler(MultiHandler([stderr_handler, syslog_handler,
                                 buildlog_handler]))

    getLogger("boto").setLevel(INFO)
    return
setup_logging()

class Distribution(object):
    s3_region = "us-west-2"
    bucket_name = "dist.kanga.org"

    os_prefixes = {
        'amzn': "AmazonLinux",
        'fedora': "Fedora",
        'rhel': "RHEL",
        'ubuntu': "Ubuntu",
    }
    dist_suffixes = {
        'amzn': {
            "2014.09": ".amzn1",
            "2015.03": ".amzn1",
        },
    }

    def __init__(self, s3_region=None, bucket_name=None):
        super(Distribution, self).__init__()
        self.s3_region = (
            s3_region if s3_region else Distribution.s3_region)
        self.bucket_name = (
            bucket_name if bucket_name else Distribution.bucket_name)

        self.linux_dist, self.dist_version = get_os_version()
        self.os_prefix = self.os_prefixes[self.linux_dist] + "/"
        self.dist_prefix = self.os_prefix + self.dist_version + "/"
        self.dist_suffix = self.dist_suffixes.get(self.linux_dist, "")
        if isinstance(self.dist_suffix, dict):
            self.dist_suffix = self.dist_suffix.get(self.dist_version, "")

        return

class KeyManager(object):
    default_region = "us-west-2"
    bucket_name = "dist-admin"
    key_name = "dist-admin"
    role_arn = "arn:aws:iam::557925715019:role/dist-admin"
    role_external_id = None
    role_session_name = "dist-admin"
    
    def __init__(self, s3_region=None, kms_region=None, sts_region=None,
                 bucket_name=None, key_name=None, role_arn=None,
                 role_session_name=None, role_external_id=None):
        super(KeyManager, self).__init__()
        self.s3_region = (
            s3_region if s3_region else KeyManager.default_region)
        self.kms_region = (
            kms_region if kms_region else KeyManager.default_region)
        self.sts_region = (
            sts_region if sts_region else KeyManager.default_region)
        self.bucket_name = (
            bucket_name if bucket_name else KeyManager.bucket_name)
        self.key_name = (
            key_name if key_name else KeyManager.key_name)
        self.role_arn = (
            role_arn if role_arn else KeyManager.role_arn)
        self.role_session_name = (
            role_session_name if role_session_name
            else KeyManager.role_session_name)
        self.role_external_id = (
            role_external_id if role_external_id
            else KeyManager.role_external_id)

        self.encrypted_private_key = None
        self.public_key = None
        self.role_credentials = None
        self.s3 = None
        self.kms = None
        return

    def assume_key_manager_role(
            self, aws_access_key_id, aws_secret_access_key,
            mfa_serial_number, mfa_code):
        sts = boto.sts.connect_to_region(
            region=self.sts_region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            is_secure=True)
        assumed_role = sts.assume_role(
            role_arn=self.role_arn, role_session_name=self.role_session_name,
            external_id=self.role_external_id,
            mfa_serial_number=mfa_serial_number,
            mfa_token=mfa_token)
        self.role_credentials = assumed_role.credentials
        self.s3 = boto.s3.connect_to_region(
            region=self.s3_region,
            aws_access_key_id=self.role_credentials.access_key,
            aws_secret_access_key=self.role_credentials.secret_key,
            security_token=self.role_credentials.security_token,
            calling_format=OrdinaryCallingFormat(),
            is_secure=True)
        self.kms = boto.kms.connect_to_region(
            region=self.kms_region,
            aws_access_key_id=self.role_credentials.access_key,
            aws_secret_access_key=self.role_credentials.secret_key,
            security_token=self.role_credentials.security_token,
            is_secure=True)
        return

    def get_private_key_from_gpg(self):
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        result, out, err = invoke("gpg", "--export-secret-keys", "--armor",
                                  suppress_output=True, return_all=True)
        if result:
            raise RuntimeError("Failed to invoke gpg: exit code %d" % result)

        plaintext_key = out
        self.encrypted_private_key = (
            self.kms.encrypt(self.key_name, plaintext_key)["CiphertextBlob"])
        return self.encrypted_private_key

    def get_public_key_from_gpg(self):
        result, out, err = invoke("gpg", "--export", "--armor",
                                  suppress_output=True, return_all=True)
        if result:
            raise RuntimeError("Failed to invoke gpg export: exit code %d" %
                               result)

        self.public_key = out
        return self.public_key

    def put_private_key_to_gpg(self):
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        plaintext = self.kms.decrypt(self.encrypted_private_key)
        result, out, err = invoke("gpg", "--import", stdin=plaintext,
                                  suppress_output=True, return_all=True)

        if result:
            raise RuntimeError("Failed to invoke gpg import: exit code %d" %
                               result)
        
        return

    def upload_private_key(self):
        if not self.encrypted_private_key:
            raise RuntimeError("private_key not set")
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.new_key(self.key_name + ".private.enc")
        key.set_contents_from_string(
            self.encrypted_private_key, policy='private')
        return

    def download_private_key(self):
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.get_key(self.key_name + ".private.enc")
        self.encrypted_private_key = key.read()
        return

    def upload_public_key(self):
        if not self.public_key:
            raise RuntimeError("public_key not set")
        if not self.role_credentials:
            raise RuntimeError("assume_key_manager_role not called")

        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.new_key(self.key_name + ".public")
        key.set_contents_from_string(
            self.public_key, policy='private')
        return

    def download_public_key(self):
        bucket = self.s3.get_bucket(self.bucket_name)
        key = bucket.get_key(self.key_name + ".public")
        self.public_key = key.read()
        return

def invoke(*cmd, **kw):
    """
    invoke(*cmd)
    
    Invoke a command, logging stdout and stderr to syslog 
    """
    suppress_output = kw.pop("suppress_output", False)
    return_all = kw.pop("return_all", False)
    error_ok = kw.pop("error_ok", False)
    stdin = kw.pop("stdin", "")

    if kw:
        raise ValueError("Unknown keyword argument %s" % sorted(kw.keys())[0])

    log.info("Invoking %r", cmd)
    proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate(stdin)

    if not suppress_output:
        out = out.strip()
        if out:
            log.info("stdout:")
            for line in out.split("\n"):
                log.info("%s", line)
        err = err.strip()
        if err:
            log.warning("stderr:")
            for line in err.split("\n"):
                log.warning("%s", line)
    
    if return_all:
        return (proc.returncode, out, err)

    if proc.returncode != 0:
        if not error_ok:
            msg = ("Failed to invoke %r: exit code %d" %
                   (cmd, proc.returncode))
            log.error(msg)
            raise RuntimeError(msg)
        else:
            msg = ("Invocation of %r resulted in non-zero exit code %d" %
                   (cmd, proc.returncode))
            log.info(msg)

    return (proc.returncode == 0)
