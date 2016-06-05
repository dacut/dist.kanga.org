#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from os import getenv
from os.path import basename, exists
from logging import (
    DEBUG, FileHandler, Formatter, getLogger, Handler, INFO, StreamHandler)
from logging.handlers import SysLogHandler
from syslog import LOG_LOCAL1
from time import strftime
from sys import argv, stderr

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

    handlers = []
    buildlog_handler = FileHandler(getenv("HOME") + "/build.log")
    buildlog_handler.setFormatter(
        Log8601Formatter(progname + " %(asctime)s %(levelname)s: %(message)s"))
    handlers.append(buildlog_handler)

    stderr_handler = StreamHandler(stderr)
    stderr_handler.setFormatter(
        Log8601Formatter("%(asctime)s %(name)s %(levelname)s %(filename)s:%(lineno)s: %(message)s"))
    handlers.append(stderr_handler)
    
    if exists("/dev/log"):
        syslog_handler = SysLogHandler(
            address="/dev/log", facility=LOG_LOCAL1)
        syslog_handler.setFormatter(
            Log8601Formatter(progname +
                             " %(asctime)s %(levelname)s: %(message)s"))
        handlers.append(syslog_handler)


    log.addHandler(MultiHandler(handlers))

    getLogger("boto").setLevel(INFO)
    getLogger("boto3").setLevel(INFO)
    getLogger("botocore").setLevel(INFO)
    return

setup_logging()

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
