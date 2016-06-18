#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from botocore.exceptions import ClientError
import boto3
from getopt import getopt, GetoptError
from json import load as json_load
from os import getenv, makedirs
from os.path import basename, dirname, exists, isdir
from re import compile as re_compile
from sys import argv, exit, stderr, stdout, version_info
from tempfile import gettempdir
from urllib2 import urlopen

from .distribution import Distribution
from .logging import log
from .platform import invoke
from .s3 import get_object_to_file

BLOCK_SIZE = 65536
PUBLIC_READ = "public-read"
REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
VAR_REGEX = re_compile(r"(?<!\\)@([a-zA-Z_][a-zA-Z0-9_]*)@")

class Package(Distribution):
    """
    Build orchestration for a single package.
    """

    def __init__(self, name, version, distributions="*", **kw):
        """
        Package(name, version) -> Package

        Create a new package with the given name and version.
        """
        super(Package, self).__init__()
        self.name = name
        self.version = version
        self.last_build = None
        self.last_package = None
        self.last_source = None
        self.current_build = None

        if distributions == "*":
            self.distributions = ["amzn", "fedora", "rhel", "debian", "ubuntu"]
        else:
            self.distributions = distributions

        for key, value in kw.iteritems():
            setattr(self, key, value)

        if self.linux_dist in ("amzn", "fedora", "rhel"):
            self.get_latest = self.get_latest_rpm
            self.build = self.build_rpm
            self.has_diffs = self.has_diffs_rpm
            self.upload = self.upload_rpm
            self.srpm_name = self.rpm_name = None
            self.topdir = getenv("HOME") + "/rpmbuild"
        # elif self.linux_dist in ("debian", "ubuntu"):
        #     self.get_latest = self.get_latest_deb
        #     self.build = self.build_deb
        #     self.has_diffs = self.has_diffs_deb
        #     self.upload = self.upload_deb
        else:
            raise NotImplementedError(
                "Cannot build for distribution %r" % self.linux_dist)

        self.binary_s3_prefix = self.dist_prefix + "RPMS/x86_64/"
        self.source_s3_prefix = self.dist_prefix + "SRPMS/"

        self.s3 = boto3.client("s3", region_name=self.s3_region)
        self.bucket_name = self.bucket_name

        return

    @property
    def kanga_build(self):
        """
        Allow SPEC files to refer to @kanga_build@.
        """
        return self.current_build

    def build_rpm(self):
        """
        pkg.build_rpm()

        Create RPM and SRPM packages for RedHat and variants.
        """
        spec_vars = {}
        this_dir = dirname(__file__)
        spec_file_in = "%s/SPECS/%s.spec.%s.in" % (
            this_dir, self.name, self.linux_dist)
        spec_file_out = "%s/SPECS/%s.spec.%s" % (
            self.topdir, self.name, self.linux_dist)

        # Create rpmbuild directories
        for dir in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            path = "%s/%s" % (self.topdir, dir)
            if not exists(path):
                makedirs(path)
            
        if self.last_build is None:
            self.current_build = 0
        else:
            self.current_build = self.last_build + 1

        log.info("Replacing metavariables from SPEC file %s",
                 spec_file_in)
        with open(spec_file_in, "r") as ifd:
            # Replace metavariables.
            spec_data = ifd.read()
            start = 0

            while start < len(spec_data):
                m = VAR_REGEX.search(spec_data, start)
                if not m:
                    break
                
                variable = m.group(1)
                replacement = str(getattr(self, variable, ""))
                
                log.debug("Replacing %s with %r", variable, replacement)
                
                spec_data = (
                    spec_data[:m.start(0)] + replacement +
                    spec_data[m.end(0):])
                start = m.start(0) + len(replacement)
            
            with open(spec_file_out, "w") as ofd:
                ofd.write(spec_data)

        log.info("SPEC file written to %s", spec_file_out)

        # Parse the spec file for build variables.
        for line in spec_data.split("\n"):
            line = line.strip()

            # Stop looking for variables at the start of a section.
            if line in {"%description", "%prep", "%build", "%check",
                        "%install", "%post", "%postun", "%files", "%package"}:
                break

            # Ignore empty lines and lines starting with directives.
            if not line or line.startswith("%") or ":" not in line:
                continue
            
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key in spec_vars:
                spec_vars[key] += " " + value
            else:
                spec_vars[key] = value

        # If Source is present, rename it to Source0.
        if "Source" in spec_vars:
            if "Source0" in spec_vars:
                raise ValueError(
                    "SPEC file cannot declare both Source and Source0")
            spec_vars["Source0"] = spec_vars["Source"]

        # Download all source files.
        source_id = 0
        while "Source%d" % source_id in spec_vars:
            source = spec_vars["Source%d" % source_id]
            dest = self.topdir + "/SOURCES/" + basename(source)
            log.info("Downloading Source%d from %s", source_id, source)
            self.download(source, dest)
            source_id += 1

        log.debug("spec_vars: %r", spec_vars)

        # Set the RPM and SRPM names
        name = spec_vars["Name"].strip()
        version = spec_vars["Version"].strip()
        release = (spec_vars["Release"].strip()
                   .replace("%{kanga_build}", str(self.current_build))
                   .replace("%{dist}", self.dist_suffix))

        self.rpm_name = "%s-%s-%s.x86_64.rpm" % (name, version, release)
        self.srpm_name = "%s-%s-%s.src.rpm" % (name, version, release)

        # Install any necessary package prerequisites
        pkg_list = spec_vars.get("BuildRequires", "").strip().split()
        invoke("sudo", "yum", "-y", "install", *pkg_list)
        invoke("rpmbuild", "--define", "_topdir " + self.topdir, "-ba",
               spec_file_out)
        return

    def get_latest_rpm(self):
        """
        pkg.get_latest_rpm()

        Download the latest RPM and SRPM packages for RedHat and variants.
        """
        # Add ${pkg_name}-${pkg_version} to the source prefix; after that is
        # -${build_version}, but we want to iterate over the builds.
        rpm_prefix = (
            self.binary_s3_prefix + self.name + "-" + self.version + "-")

        list_kw = {"Bucket": self.bucket_name, "Prefix": rpm_prefix}
        rpm_candidates = []

        while True:
            result = self.s3.list_objects_v2(**list_kw)

            for s3obj in result.get("Contents", []):
                rpm_candidates.append(s3obj["Key"])

            if not result["IsTruncated"]:
                break
            
            list_kw["ContinuationToken"] = result["NextContinuationToken"]

        log.debug("Looking for previous RPMs using prefix %s", rpm_prefix)

        for rpm_candidate in rpm_candidates:
            assert rpm_candidate.startswith(rpm_prefix)
            suffix = rpm_candidate[len(rpm_prefix):]
            build = int(suffix.split(".", 1)[0])

            if self.last_build is None or self.last_build < build:
                self.last_build = build
                last_key = rpm_candidate

            log.debug("Candidate found: %s", rpm_candidate)

        if self.last_build is not None:
            if not exists(self.topdir + "/RPMS/x86_64"):
                makedirs(self.topdir + "/RPMS/x86_64")
            filename = "%s/RPMS/x86_64/%s" % (
                self.topdir, last_key.rsplit("/", 1)[1])
            log.debug("Retrieving %s", last_key)

            get_object_to_file(
                self.s3, Bucket=self.bucket_name, Key=last_key,
                File=filename)

            self.last_package = filename
            log.debug("Last build downloaded to %s", filename)

            # Attempt to download the SRPM too
            if not exists(self.topdir + "/SRPMS"):
                makedirs(self.topdir + "/SRPMS")
            srpm_name = "%s-%s-%d%s.src.rpm" % (
                self.name, self.version, self.last_build, self.dist_suffix)
            srpm_key = self.source_s3_prefix + srpm_name
            filename = self.topdir + "/SRPMS/" + srpm_name

            log.debug("Attempting to retrieve SRPM %s", srpm_key)
            try:
                get_object_to_file(
                    self.s3, Bucket=self.bucket_name, Key=srpm_key,
                    File=filename)
                self.last_source = filename
            except ClientError as e:
                log.debug("SRPM not found: %s", e)
        else:
            log.debug("No previous builds found.")

        return

    def has_diffs_rpm(self):
        """
        pkg.has_diffs_rpm() -> bool

        Indicates whether the newly built RPM has differences vs. the
        latest RPM.  If the latest RPM isn't available, this is always
        True.
        """
        if self.last_package is None or self.last_source is None:
            return True

        return (
            self.diff_rpm(self.last_package, self.topdir + "/RPMS/x86_64/" + self.rpm_name) or
            self.diff_rpm(self.last_source, self.topdir + "/SRPMS/" + self.srpm_name,
                          ignore_spec=True))

    def upload_rpm(self):
        """
        pkg.upload_rpm()

        Upload the RPM and SRPM packages.
        """
        key_name = self.binary_s3_prefix + self.rpm_name
        log.info("Uploading %s to %s", self.rpm_name, key_name)

        with open(self.topdir + "/RPMS/x86_64/" + self.rpm_name, "r") as ifd:
            self.s3.put_object(
                ACL=PUBLIC_READ,
                Body=ifd,
                Bucket=self.bucket_name,
                Key=key_name,
                StorageClass=REDUCED_REDUNDANCY)

        key_name = self.source_s3_prefix + self.srpm_name
        log.info("Uploading %s to %s", self.srpm_name, key_name)

        with open(self.topdir + "/SRPMS/" + self.srpm_name, "r") as ifd:
            self.s3.put_object(
                ACL=PUBLIC_READ,
                Body=ifd,
                Bucket=self.bucket_name,
                Key=key_name,
                StorageClass=REDUCED_REDUNDANCY)

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
        the packages.json file).
        """
        with open(dirname(__file__) + "/packages.json", "r") as fd:
            return [cls(**pkgdata) for pkgdata in json_load(fd)]

    # pylint: disable=E0401
    @classmethod
    def diff_rpm(cls, rpm_filename_1, rpm_filename_2, ignore_spec=False):
        """
        Package.diff_rpm(rpm_filename_1, rpm_filename_2) -> bool

        Indicate whether two RPM package files differ.
        """
        # Note: We can't use rpmdiff -- it diffs the Provides header
        # unconditionally, so it always indicates the RPMs differ.

        rpm_basename_1 = basename(rpm_filename_1)
        rpm_basename_2 = basename(rpm_filename_2)

        if isdir("/usr/share/rpmlint"):
            import site
            site.addsitedir("/usr/share/rpmlint")
        
        pymajmin = "%d.%d" % (version_info.major, version_info.minor)
        if isdir("/usr/lib64/python%s/dist-packages" % pymajmin):
            import site
            site.addsitedir("/usr/lib64/python%s/dist-packages" % pymajmin)

        from Pkg import Pkg
        from rpm import (
            RPMTAG_DESCRIPTION, RPMTAG_GROUP, RPMTAG_LICENSE, RPMTAG_NAME,
            RPMTAG_POSTIN, RPMTAG_POSTTRANS, RPMTAG_POSTUN, RPMTAG_PREIN,
            RPMTAG_PRETRANS, RPMTAG_PREUN, RPMTAG_SUMMARY, RPMTAG_URL)

        log.debug("diff_rpm: %s vs %s", rpm_basename_1, rpm_basename_2)

        tmpdir = gettempdir()
        rpm1 = Pkg(rpm_filename_1, tmpdir).header
        rpm2 = Pkg(rpm_filename_2, tmpdir).header

        # Check for differences in tags
        for tag in (RPMTAG_DESCRIPTION, RPMTAG_GROUP, RPMTAG_LICENSE,
                    RPMTAG_NAME, RPMTAG_POSTIN, RPMTAG_POSTTRANS,
                    RPMTAG_POSTUN, RPMTAG_PREIN, RPMTAG_PRETRANS, RPMTAG_PREUN,
                    RPMTAG_SUMMARY, RPMTAG_URL):
            if rpm1[tag] != rpm2[tag]:
                log.debug("tag %s differs: %r vs %r", tag, rpm1[tag], rpm2[tag])
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

            log.debug("header_name=%r, rpm1_hdata=%r, rpm2_hdata=%r",
                     header_name, rpm1_hdata, rpm2_hdata)

            # Make sure each item is present in the other.
            for entry in rpm1_hdata:
                if entry not in rpm2_hdata:
                    log.debug("Present in %s, missing in %s: %s",
                              rpm_basename_1, rpm_basename_2, entry)
                    return True
                
            for entry in rpm2_hdata:
                if entry not in rpm1_hdata:
                    return True
                    log.debug("Missing in %s, present in %s: %s",
                              rpm_basename_1, rpm_basename_2, entry)

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

            if metadata2 is None:
                log.debug("File %s is missing from %s", filename,
                          rpm_basename_2)
                return True

            if ignore_spec and (
                    filename.endswith(".spec") or ".spec." in filename):
                continue

            if (metadata1[:2] != metadata2[:2] or
                    metadata1[3:] != metadata2[3:]):
                log.debug("File %s metadata differs: %s vs %s", filename,
                          metadata1, metadata2)
                return True

        # Only need to check for existence in rpm1_files; common files have
        # already passed the comparison.
        for filename in rpm2_files.iterkeys():
            if rpm1_files.get(filename) is None:
                log.debug("File %s is missing from %s", filename,
                          rpm_basename_1)
                return True

        log.debug("RPMs are equivalent")
        # RPMs are equivalent.
        return False

def localbuild():
    do_list = False
    
    try:
        opts, args = getopt(argv[1:], "hl", ["help", "list"])
        for opt, arg in opts:
            if opt in ("-h", "--help",):
                localbuild_usage(stdout)
                return 0
            elif opt in ("-l", "--list",):
                do_list = True

        build_packages = args
    except GetoptError as e:
        print(str(e), file=stderr)
        localbuild_usage()
        return 1

    log.info("Invoking localbuild")
    try:
        for package in Package.get_packages():
            if len(build_packages) > 0 and package.name not in build_packages:
                continue

            if do_list:
                if package.linux_dist in package.distributions:
                    print("%s-%s" % (package.name, package.version))
                    
                continue

            if package.linux_dist not in package.distributions:
                log.info("Skipping %s (not supported on %s)", package.name,
                         package.linux_dist)
                continue

            log.info("Building %s-%s", package.name, package.version)

            package.get_latest()
            if package.last_build is not None:
                log.info("Previous build is %d", package.last_build)
            else:
                log.info("No previous build")

            package.build()

            if package.has_diffs():
                log.info("Build %d differs from previous build; uploading.",
                         package.current_build)
                package.upload()
                log.info("Upload complete.")
            else:
                log.info("Build %d is the same as previous build %d; skipping "
                         "upload.", package.current_build, package.last_build)
    except:
        log.error("localbuild failed", exc_info=True)
        return 1
    else:
        log.info("localbuild succeeded")
        return 0

def localbuild_usage(fd=stderr):
    fd.write("""\
Usage: kdist-localbuild [options] <build_packages...>
Build packages on this platform and upload any changes to the distribution
server.

Options:
    -h | --help
        Show this usage information.

    -l | --list
        Print a list of packages available for building.

If build_packages is not specified, all packages are built.
""")
    fd.flush()
    return

if __name__ == "__main__":
    exit(localbuild())
