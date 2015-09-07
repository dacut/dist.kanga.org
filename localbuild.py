#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto.s3
from csv import reader as csv_reader
from os import makedirs
from os.path import basename, dirname, exists
from re import compile as re_compile
from subprocess import PIPE, Popen
from syslog import (
    LOG_ERR, LOG_INFO, LOG_LOCAL1, LOG_WARNING, openlog, syslog)
from urllib2 import urlopen

openlog("localbuild.py", 0, LOG_LOCAL1)

id_regex = re_compile(r'^\s*ID=(?:"([^"]*)"|([^ ]*))\s*$')
version_regex = re_compile(r'^\s*VERSION=(?:"([^"]*)"|([^ ]*))\s*$')

linux_dist = None
dist_version = None

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

class Package(object):
    """
    Build orchestration for a single package.
    """

    s3_region = "us-west-2"
    bucket_name = "dist.kanga.org"
    os_prefix = {
        'amzn': "AmazonLinux",
        'fedora': "Fedora",
        'rhel': "RHEL",
        'ubuntu': "Ubuntu",
    }

    def __init__(self, name, version):
        """
        Package(name, version) -> Package

        Create a new package with the given name and version.
        """
        super(Package, self).__init__()
        self.name = name
        self.version = version
        self.last_build = None
        self.last_package = None
        return

    def build(self):
        """
        pkg.build()

        Build this package (delegating to an OS appropriate build method).
        """
        linux_dist = get_os_version()[0]
        if linux_dist in ("amzn", "fedora", "rhel"):
            return self.rpm_build()
        elif linux_dist in ("debian", "ubuntu"):
            return self.deb_build()
        else:
            raise NotImplementedError(
                "Cannot build for distribution %r" % linux_dist)
    
    def rpm_build(self):
        """
        pkg.rpm_build()

        Create RPM and SRPM packages for RedHat and variants.
        """
        spec_data = {}
        spec_file_in = "SPECS/%s.spec.%s.in" % (self.name, linux_dist)
        spec_file_out = "SPECS/%s.spec.%s" % (self.name, linux_dist)

        if self.last_build is None:
            self.build = 0
        else:
            self.build = self.last_build + 1

        with open(spec_file_in, "r") as ifd:
            output = ifd.read().replace("%{kanga_build}", str(self.build))
            with open(spec_file_out, "w") as ofd:
                ofd.write(output)

            ifd.seek(0, 0)
            for line in ifd:
                if line.startswith("%"):
                    break
                line = line.strip()
                if not line:
                    continuex50
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

        self.invoke("rpmbuild", "-ba", spec_file_out)

    def get_latest_existing_rpm(self):
        """
        pkg.get_latest_existing_rpm()

        Download the latest RPM and SRPM packages for RedHat and variants.
        """
        os, version = get_os_version()

        # Open the bucket for the distribution.
        s3 = boto.s3.connect_to_region(self.s3_region)
        bucket = s3.get_bucket(bucket_name)

        # The base for all packages for this OS/version combo is at
        # ${os_prefix}/${version}/
        osver_prefix = self.os_prefix(os) + "/" + version + "/"

        # Add RPMS/x86_64/ for binaries; we don't deal with 32-bit any more.
        # Then ${pkg_name}-${pkg_version}; after that is -${build_version},
        # but we want to iterate over that.
        rpm_prefix = (osver_prefix + "RPMS/x86_64/" + self.name + "-" +
                      self.version)
        
        rpm_candidates = bucket.list(prefix=rpm_prefix)

        for rpm_candidate in rpm_candidates:
            assert rpm_candidate.name.startswith(rpm_prefix)
            suffix = rpm_candidate[len(rpm_prefix):]
            build = int(suffix.split(".", 1)[0])

            if self.last_build is None or self.last_build < build:
                self.last_build = build
                last_key = rpm_candidate

        if self.last_build is not None:
            os.makedirs("RPMS/x86_64")
            filename = "RPMS/x86_64/" + last_key.name.rsplit("/", 1)[1]
            last_key.get_contents_to_filename(filename)
            self.last_package = filename
            
        return

    def rpm_upload(self):
        """
        pkg.rpm_upload()

        Upload the RPM and SRPM packages if they differ from the latest
        version.
        """
        raise NotImplementedError()

    def invoke(self, *cmd):
        """
        pkg.invoke(*cmd)

        Invoke a command, logging stdout and stderr to syslog 
        """
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
        """
        pkg.download(source, dest)

        Download the source URL to the destination file.
        """
        dest_dir = dirname(dest)
        if not exists(dest_dir):
            makedirs(dest_dir)

        conn = urlopen(source)
        with open(dest, "wb") as ofd:
            ofd.write(conn.read())

        return

    @classmethod
    def get_packages(cls):
        """
        Package.get_packages()

        Returns a Package object for all known packages (as specified in
        the packages.csv file).
        """
        results = []

        with open(dirname(__file__) + "/packages.csv", "r") as fd:
            reader = csv_reader(fd, dialect='excel-tab')
            header = reader.next()

            for row in reader:
                kw = dict(zip(header, row))
                results.append(cls(**kw))

        return results

def main():
    for package in Package.get_packages():
        package.build()
        package.upload()

if __name__ == "__main__":
    main()
