#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from csv import reader as csv_reader
from logging import DEBUG, Formatter, getLogger, Handler, INFO, StreamHandler
from logging.handlers import SysLogHandler
from os import getenv, makedirs
from os.path import basename, dirname, exists, isdir
from re import compile as re_compile
from subprocess import PIPE, Popen
from sys import stderr
from syslog import LOG_LOCAL1
from tempfile import gettempdir
from time import strftime
from urllib2 import urlopen

id_regex = re_compile(r'^\s*ID=(?:"([^"]*)"|([^ ]*))\s*$')
version_regex = re_compile(r'^\s*VERSION=(?:"([^"]*)"|([^ ]*))\s*$')

linux_dist = None
dist_version = None

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
        return "%s.%s" % (
            strftime("%Y-%m-%dT%H:%M:%S", self.converter(record.created)),
            record.msecs)

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
        self.linux_dist, self.dist_version = get_os_version()

        if self.linux_dist in ("amzn", "fedora", "rhel"):
            self.get_latest = self.get_latest_rpm
            self.build = self.build_rpm
            self.has_diffs = self.has_diffs_rpm
            self.upload = self.upload_rpm
        elif self.linux_dist in ("debian", "ubuntu"):
            self.get_latest = self.get_latest_deb
            self.build = self.build_deb
            self.has_diffs = self.has_diffs_deb
            self.upload = self.upload_deb
        else:
            raise NotImplementedError(
                "Cannot build for distribution %r" % linux_dist)

        self.os_prefix = self.os_prefixes[self.linux_dist]
        self.dist_suffix = self.dist_suffixes.get(self.linux_dist, "")
        if isinstance(self.dist_suffix, dict):
            self.dist_suffix = self.dist_suffix.get(self.dist_version, "")

        self.binary_s3_prefix = (
            self.os_prefix + "/" + self.dist_version + "/RPMS/x86_64/")
        self.source_s3_prefix = (
            self.os_prefix + "/" + self.dist_version + "/SRPMS/")

        # Boto can't handle dots in bucket names (certificate validation
        # issues with TLS), so we have to use the older calling format.
        self.s3 = boto.s3.connect_to_region(
            self.s3_region, calling_format=OrdinaryCallingFormat())

        # Open the bucket for the distribution.
        self.bucket = self.s3.get_bucket(self.bucket_name)
        
        return

    def build_rpm(self):
        """
        pkg.build_rpm()

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

        # Get the RPM name
        self.rpm_name = (
            spec_data.get("Name").strip() + "-" +
            spec_data.get("Version").strip() + "-" +
            spec_data.get("Release").strip() + ".x86_64.rpm")
        self.rpm_name = self.rpm_name.replace(
            "%{kanga_build}", str(self.build))
        self.rpm_name = self.rpm_name.replace("%{dist}", self.dist_suffix)
        
        # Install any necessary package prerequisites
        pkg_list = spec_data.get("BuildRequires", "").strip().split()
        self.invoke("sudo", "yum", "-y", "install", *pkg_list)

        self.invoke("rpmbuild", "-ba", spec_file_out)

    def get_latest_rpm(self):
        """
        pkg.get_latest_rpm()

        Download the latest RPM and SRPM packages for RedHat and variants.
        """
        # Add ${pkg_name}-${pkg_version} to the source prefix; after that is
        # -${build_version}, but we want to iterate over the builds.
        rpm_prefix = (
            self.binary_s3_prefix + self.name + "-" + self.version + "-")
        rpm_candidates = self.bucket.list(prefix=rpm_prefix)

        for rpm_candidate in rpm_candidates:
            assert rpm_candidate.name.startswith(rpm_prefix)
            suffix = rpm_candidate.name[len(rpm_prefix):]
            build = int(suffix.split(".", 1)[0])

            if self.last_build is None or self.last_build < build:
                self.last_build = build
                last_key = rpm_candidate

        if self.last_build is not None:
            if not exists ("RPMS/x86_64"):
                makedirs("RPMS/x86_64")
            filename = "RPMS/x86_64/" + last_key.name.rsplit("/", 1)[1]
            last_key.get_contents_to_filename(filename)
            self.last_package = filename
            
        return

    def has_diffs_rpm(self):
        """
        pkg.has_diffs_rpm() -> bool

        Indicates whether the newly built RPM has differences vs. the
        latest RPM.  If the latest RPM isn't available, this is always
        True.
        """
        if self.last_package is None:
            return True

        return self.diff_rpm(self.last_package, "RPMS/x86_64/" + self.rpm_name)

    def upload_rpm(self):
        """
        pkg.upload_rpm()

        Upload the RPM and SRPM packages if they differ from the latest
        version.
        """
        key_name = self.binary_s3_prefix + self.rpm_name
        key = self.bucket.new_key(key_name)
        key.set_contents_from_filename(
            "RPMS/x86_64/" + self.rpm_name, reduced_redundancy=True,
            policy='public-read')

    def invoke(self, *cmd, **kw):
        """
        pkg.invoke(*cmd)

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

    @classmethod
    def diff_rpm(cls, rpm_filename_1, rpm_filename_2):
        """
        Package.diff_rpm(rpm_filename_1, rpm_filename_2) -> bool

        Indicate whether two RPM package files differ.
        """
        # Note: We can't use rpmdiff -- it diffs the Provides header
        # unconditionally, so it always indicates the RPMs differ.

        if isdir("/usr/share/rpmlint"):
            import site
            site.addsitedir("/usr/share/rpmlint")
        from Pkg import Pkg
        from rpm import (
            RPMTAG_DESCRIPTION, RPMTAG_GROUP, RPMTAG_LICENSE, RPMTAG_NAME,
            RPMTAG_POSTIN, RPMTAG_POSTTRANS, RPMTAG_POSTUN, RPMTAG_PREIN,
            RPMTAG_PRETRANS, RPMTAG_PREUN, RPMTAG_SUMMARY, RPMTAG_URL)
        tmpdir = gettempdir()
        rpm1 = Pkg(rpm_filename_1, tmpdir).header
        rpm2 = Pkg(rpm_filename_2, tmpdir).header

        # Check for differences in tags
        for tag in (RPMTAG_DESCRIPTION, RPMTAG_GROUP, RPMTAG_LICENSE,
                    RPMTAG_NAME, RPMTAG_POSTIN, RPMTAG_POSTTRANS,
                    RPMTAG_POSTUN, RPMTAG_PREIN, RPMTAG_PRETRANS, RPMTAG_PREUN,
                    RPMTAG_SUMMARY, RPMTAG_URL):
            if rpm1[tag] != rpm2[tag]:
                return True

        # Ignore provides, but make sure requires, conflicts, and obsoletes
        # headers are the same.
        for header_name in ('REQUIRE', 'CONFLICT', 'OBSOLETE'):
            rpm1_values = rpm1[header_name + 'S']
            rpm2_values = rpm2[header_name + 'S']
            rpm1_flags = rpm1[header_name + 'FLAGS']
            rpm2_flags = rpm2[header_name + 'FLAGS']
            rpm1_versions = rpm1[header_name + 'VERSION']
            rpm2_versions = rpm2[header_name + 'VERSION']

            if not isinstance(rpm1_flags, (list, tuple)):
                rpm1_flags = [rpm1_flags]
            if not isinstance(rpm2_flags, (list, tuple)):
                rpm2_flags = [rpm2_flags]

            # These are parallel arrays, so we zip them up for easy searching.
            rpm1_hdata = set(zip(rpm1_values, rpm1_flags, rpm1_versions))
            rpm2_hdata = set(zip(rpm2_values, rpm2_flags, rpm2_versions))

            # Make sure each item is present in the other.
            for entry in rpm1_hdata:
                if entry not in rpm2_hdata:
                    return True

            for entry in rpm2_hdata:
                if entry not in rpm1_hdata:
                    return True

        # All tags and headers are equal.  Compare file metadata.
        # fiFromHeader() returns a file metadata iterator; the fields returned
        # by the iterator are (name, size, mode, timestamp, flags, device,
        # inode, nlinks, state, vflags, user, group, digest)
        #
        # We ignore the timestamp.
        rpm1_files = dict([(file_data[0], file_data[1:])
                           for file_data in rpm1.fiFromHeader()])
        rpm2_files = dict([(file_data[0], file_data[1:])
                           for file_data in rpm2.fiFromHeader()])

        for filename, metadata1 in rpm1_files.iteritems():
            metadata2 = rpm2_files.get(filename)
            if (metadata2 is None or
                metadata1[:2] != metadata2[:2] or
                metadata1[3:] != metadata2[3:]):
                return False

        # Only need to check for existence in rpm1_files; common files have
        # already passed the comparison.
        for filename in rpm2_files.iterkeys():
            if rpm1_files.get(filename) is None:
                return False

        # RPMs are equivalent.
        return True

def main():
    log.info("Invoking localbuild.py")
    try:
        for package in Package.get_packages():
            log.info("Building %s-%s", package.name, package.version)
            package.get_latest()
            if package.last_build is not None:
                log.info("Previous build is %d", package.last_build)
            else:
                log.info("No previous build")
            package.build()

            if package.has_diffs():
                log.info("Build %d differs from previous build; uploading.",
                         package.build)
                package.upload()
                log.info("Upload complete.")
            else:
                log.info("Build %d is the same as previous build %d; skipping "
                         "upload.", package.build, package.last_build)
    except Exception as e:
        log.error("localbuild.py failed", exc_info=True)
    else:
        log.info("localbuild.py succeeded")

if __name__ == "__main__":
    log = getLogger()
    log.setLevel(DEBUG)
    stderr_handler = StreamHandler(stderr)
    syslog_handler = SysLogHandler(facility=LOG_LOCAL1)
    formatter = Log8601Formatter("%(asctime)s %(levelname)s: %(message)s")
    stderr_handler.setFormatter(formatter)
    syslog_handler.setFormatter(formatter)
    log.addHandler(MultiHandler([stderr_handler, syslog_handler]))

    getLogger("boto").setLevel(INFO)
    main()
