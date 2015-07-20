#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
from csv import reader as csv_reader
from os import makedirs
from os.path import basename, dirname, exists
from re import compile as re_compile
from subprocess import PIPE, Popen
from syslog import (
    LOG_ERR, LOG_INFO, LOG_LOCAL1, LOG_WARNING, openlog, syslog)
from urllib2 import urlopen

openlog("localbuild.py", 0, LOG_LOCAL1)

id_regex = re_compile(r'^\s*ID=(?:("[^"]*")|([^ ]*))\s*$')
def get_linux_dist():
    if exists("/etc/os-release"):
        with open("/etc/os-release", "r") as fd:
            for line in fd:
                m = id_regex.match(line)
                if m:
                    if m.group(1):
                        return m.group(1)[1:-1]
                    else:
                        return m.group(2)
    else:
        return "rhel"
linux_dist = get_linux_dist()
            

class Package(object):
    def __init__(self, name, version):
        super(Package, self).__init__()
        self.name = name
        self.version = version
        return

    def build(self):
        if linux_dist in ("amzn", "fedora", "rhel"):
            return self.rpm_build()
        elif linux_dist in ("debian", "ubuntu"):
            return self.deb_build()
        else:
            raise NotImplementedError(
                "Cannot build for distribution %r" % linux_dist)
    
    def rpm_build(self):
        spec_data = {}
        spec_file = "SPECS/%s.spec.%s" % (self.name, linux_dist)

        with open(spec_file, "r") as fd:
            for line in fd:
                if line.startswith("%"):
                    break
                line = line.strip()
                if not line:
                    continue
                key, value = line.split(":", 1)
                spec_data[key] = value
        
        if "Source" in spec_data:
            if "Source0" in spec_data:
                raise ValueError(
                    "SPEC file cannot declare both Source and Source0")
            spec_data["Source0"] = spec_data["Source"]

        source_id = 0
        while "Source%d" % source_id in spec_data:
            source = spec_data["Source%d" % source_id]
            dest = "SOURCES/" + basename(source)
            self.download(source, dest)
            source_id += 1

        self.invoke("rpmbuild", "-ba", spec_file)

    def invoke(self, *cmd):
        syslog(LOG_INFO, "Invoking %r" % (cmd,))
        proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()

        out = out.strip()
        if out:
            syslog(LOG_INFO, "stdout:")
            for line in out.split("\n"):
                syslog(LOG_INFO, line)
        err = err.strip()
        if err:
            syslog(LOG_WARNING, "stderr:")
            for line in err.split("\n"):
                syslog(LOG_WARNING, line)

        if proc.returncode != 0:
            msg = "Failed to invoke %r: exit code %d" % (cmd, proc.returncode)
            syslog(LOG_ERR, msg)
            raise RuntimeError(msg)

        return

    def download(self, source, dest):
        dest_dir = dirname(dest)
        if not exists(dest_dir):
            makedirs(dest_dir)

        conn = urlopen(source)
        with open(dest, "wb") as ofd:
            ofd.write(conn.read())

        return

    @classmethod
    def get_packages(cls):
        results = []

        with open(dirname(__file__) + "/packages.csv", "r") as fd:
            reader = csv_reader(fd, dialect='excel-tab')
            header = reader.next()

            for row in reader:
                kw = dict(zip(header, row))
                results.append(cls(**kw))

        return results

def build_all():
    for package in Package.get_packages():
        package.build()

if __name__ == "__main__":
    build_all()
