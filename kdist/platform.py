#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from os.path import exists
from re import compile as re_compile
from subprocess import PIPE, Popen

from kdist.logging import log

ID_REGEX = re_compile(r'^\s*ID=(?:"([^"]*)"|([^ ]*))\s*$')
VERSION_REGEX = re_compile(r'^\s*VERSION=(?:"([^"]*)"|([^ ]*))\s*$')
_linux_dist = None
_dist_version = None

def get_os_version():
    """
    get_os_version() -> (str, str)

    Return the Linux distribution and version as a pair of strings.
    """
    global _linux_dist, _dist_version

    if _linux_dist is None or _dist_version is None:
        if not exists("/etc/os-release"):
            raise ValueError("File /etc/os-release not found")

        with open("/etc/os-release", "r") as fd:
            for line in fd:
                m = ID_REGEX.match(line)
                if m:
                    if m.group(1):
                        _linux_dist = m.group(1)
                    else:
                        _linux_dist = m.group(2)

                m = VERSION_REGEX.match(line)
                if m:
                    if m.group(1):
                        _dist_version = m.group(1)
                    else:
                        _dist_version = m.group(2)

        if not _linux_dist:
            raise ValueError("Failed to find ID=... line in /etc/os-release")

        if not _dist_version:
            raise ValueError("Failed to find VERSION=... line in "
                             "/etc/os-release")

    return (_linux_dist, _dist_version)

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
            log.debug("stdout:")
            for line in out.split("\n"):
                log.debug("%s", line)
        err = err.strip()
        if err:
            log.debug("stderr:")
            for line in err.split("\n"):
                log.debug("%s", line)

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

    return proc.returncode == 0

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
