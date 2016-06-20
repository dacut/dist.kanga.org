#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import getopt
import logging
import os.path
import sys
import tempfile

log = logging.getLogger("kdist.rpm")

def diff_rpm(rpm_filename_1, rpm_filename_2, ignore=()):
    """
    diff_rpm(rpm_filename_1, rpm_filename_2) -> bool

    Indicate whether two RPM package files differ in content.

    This differs from rpmdiff in that it ignores the Provides header. This
    allows us to determine whether a rebuild differs in a meaningful way.
    """
    # Note: We can't use rpmdiff -- it diffs the Provides header
    # unconditionally, so it always indicates the RPMs differ.

    rpm_basename_1 = os.path.basename(rpm_filename_1)
    rpm_basename_2 = os.path.basename(rpm_filename_2)

    # This requires rpmlint libraries.
    if os.path.isdir("/usr/share/rpmlint"):
        import site
        site.addsitedir("/usr/share/rpmlint")

    # On Amazon Linux, the RPM libraries are installed in /usr/share/rpmlint
    # and /usr/lib64/pythonX.y/dist-packages.
    pymajmin = "%d.%d" % (sys.version_info.major, sys.version_info.minor)
    if os.path.isdir("/usr/lib64/python%s/dist-packages" % pymajmin):
        import site
        site.addsitedir("/usr/lib64/python%s/dist-packages" % pymajmin)

    from Pkg import Pkg
    from rpm import (
        RPMTAG_DESCRIPTION, RPMTAG_GROUP, RPMTAG_LICENSE, RPMTAG_NAME,
        RPMTAG_POSTIN, RPMTAG_POSTTRANS, RPMTAG_POSTUN, RPMTAG_PREIN,
        RPMTAG_PRETRANS, RPMTAG_PREUN, RPMTAG_SUMMARY, RPMTAG_URL)

    log.debug("diff_rpm: %s vs %s", rpm_basename_1, rpm_basename_2)

    tmpdir = tempfile.gettempdir()
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
        for pattern in ignore:
            if fnmatch.fnmatch(filename, pattern):
                log.debug("Ignoring file %s (matches pattern %s)", filename,
                          pattern)
                continue

        metadata2 = rpm2_files.get(filename)

        if metadata2 is None:
            log.debug("File %s is missing from %s", filename,
                      rpm_basename_2)
            return True

        if (metadata1[:2] != metadata2[:2] or
                metadata1[3:] != metadata2[3:]):
            log.debug("File %s metadata differs: %s vs %s", filename,
                      metadata1, metadata2)
            return True

        log.debug("File %s is the same", filename)

    # Only need to check for existence in rpm1_files; common files have
    # already passed the comparison.
    for filename in rpm2_files.iterkeys():
        for pattern in ignore:
            if fnmatch.fnmatch(filename, pattern):
                log.debug("Ignoring file %s (matches pattern %s)", filename,
                          pattern)
                continue

        if rpm1_files.get(filename) is None:
            log.debug("File %s is missing from %s", filename,
                      rpm_basename_1)
            return True

    log.debug("RPMs are equivalent")
    return False

def main():
    ignore = set()
    logging.basicConfig(level=logging.INFO)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "dhi:",
                                   ["debug", "help", "ignore="])
    except getopt.GetoptError as e:
        print(str(e), file=sys.stderr)
        usage()
        return 2
        
    for opt, val in opts:
        if opt in ("-d", "--debug",):
            logging.getLogger().setLevel(logging.DEBUG)
        if opt in ("-h", "--help",):
            usage(sys.stdout)
            return 2
        if opt in ("-i", "--ignore",):
            for item in opt.split(","):
                ignore.add(item)

    if len(args) == 0:
        print("Missing filenames", file=sys.stderr)
        usage()
        return 2
    elif len(args) == 1:
        print("Missing second RPM filename", file=sys.stderr)
        usage()
        return 2
    elif len(args) > 2:
        print("Unknown argument %r" % args[2], file=sys.stderr)
        usage()
        return 2

    rpm_filename_1, rpm_filename_2 = args
    if diff_rpm(rpm_filename_1, rpm_filename_2, ignore):
        print("RPM files %s and %s differ" % (rpm_filename_1, rpm_filename_2))
        return 1
    else:
        return 0

def usage(fd=sys.stderr):
    fd.write("""\
Usage: %(argv0)s [options] <file1> <file2>

Indicate whether two RPM package files differ in content.

This differs from rpmdiff in that it ignores the Provides header, allowing for
the rebuild of a package to determine if there are meaningful diffs.

Options:
    -d | --debug
        Show debugging information about why the RPMs differ.

    -h | --help
        Show this usage information.

    -i <pattern> | --ignore <pattern>
        Ignore files in the RPM matching the given pattern. This may be
        specified multiple times.

Exit codes:
If the RPMs are the same, the return value is 0.
If the RPMs differ, the return value is 1.
If there was a usage error (file not found, invalid argument) or the --help
option was specified, the return value is 2.
""" % {"argv0": sys.argv[0]})
    fd.flush()

if __name__ == "__main__":
    sys.exit(main())

    
