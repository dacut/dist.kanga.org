from __future__ import absolute_import, print_function
from logging import DEBUG, Formatter, getLogger, Handler, INFO, StreamHandler
from logging.handlers import SysLogHandler
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
            int(record.msecs))

def setup_logging():
    global log

    progname = basename(argv[0])
    log = getLogger()
    log.setLevel(DEBUG)
    stderr_handler = StreamHandler(stderr)
    syslog_handler = SysLogHandler(address="/dev/log", facility=LOG_LOCAL1)
    stderr_handler.setFormatter(
        Log8601Formatter("%(asctime)s %(levelname)s: %(message)s"))
    syslog_handler.setFormatter(
        Log8601Formatter(progname + " %(asctime)s %(levelname)s: %(message)s"))
    log.addHandler(MultiHandler([stderr_handler, syslog_handler]))

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

    def __init__(self):
        super(Distribution, self).__init__()
        self.linux_dist, self.dist_version = get_os_version()
        self.os_prefix = self.os_prefixes[self.linux_dist] + "/"
        self.dist_prefix = self.os_prefix + self.dist_version + "/"
        self.dist_suffix = self.dist_suffixes.get(self.linux_dist, "")
        if isinstance(self.dist_suffix, dict):
            self.dist_suffix = self.dist_suffix.get(self.dist_version, "")

        return

def invoke(*cmd, **kw):
    """
    invoke(*cmd)
    
    Invoke a command, logging stdout and stderr to syslog 
    """
    log.info("Invoking %r", cmd)
    proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()

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

    if proc.returncode != 0:
        if not kw.get("error_ok", False):
            msg = ("Failed to invoke %r: exit code %d" %
                   (cmd, proc.returncode))
            log.error(msg)
            raise RuntimeError(msg)
        else:
            msg = ("Invocation of %r resulted in non-zero exit code %d" %
                   (cmd, proc.returncode))
            log.info(msg)

    return (proc.returncode == 0)

