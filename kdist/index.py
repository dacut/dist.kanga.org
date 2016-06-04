#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from cgi import escape as escape_html
from getopt import getopt, GetoptError
from os.path import split as split_path, splitext
from six import iteritems
from six.moves import cStringIO as StringIO
from six.moves.urllib.parse import quote as url_quote #pylint: disable=E0401
from sys import argv, stderr, stdout


class Directory(object):
    header = """\
<DOCTYPE html>
<html>
  <head><title>Index of %(display_name)s</title></head>
  <body>
    <table>
      <tr><th valign="top">&nbsp;</th><th>Name</th><th>Last modified</th>
          <th>Size</th><th>Description</th></tr>
"""

    parent_backlink = """\
      <tr><td valign="top"><img src="/icons/back.gif" alt="[DIR]"></td>\
<td><a href="%(parent_dirname)s/index.html">Parent Directory</a></td>\
<td>&nbsp;</td><td>-</td><td>&nbsp;</td></tr>
"""

    subdir_link = """\
      <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td>\
<td><a href="%(subdir_link)s/index.html">%(subdir_name)s</a></td>\
<td>&nbsp;</td><td>-</td><td>&nbsp;</td></tr>
"""

    file_link = """\
      <tr><td valign="top"><img src="/icons/%(icon_name)s" \
alt="[%(suffix_type)s]"></td>\
<td><a href="%(file_link)s">%(filename)s</a></td>\
<td>%(last_modified)s</td><td>%(size)s</td><td>%(description)s</td></tr>
"""

    footer = """\
    </table>
  </body>
</html>
"""

    suffix_types = {
        '.rpm': "RPM",
        '.deb': "DEB",
        '.txt': "TXT",
        '.ps': "PS ",
        '.pdf': "PDF",
    }

    icons = {
        '.rpm': 'binary.png',
        '.deb': 'binary.png',
        '.txt': 'text.png',
        '.ps': 'ps.png',
        '.pdf': 'pdf.png',
    }

    def __init__(self, dir_name):
        super(Directory, self).__init__()
        self.dir_name = dir_name
        self.subdirs = {}
        self.contents = {}
        return

    def add_content(self, key):
        self.contents[split_path(key.name)[-1]] = key
        return

    def add_subdir(self, name, directory):
        self.subdirs[name] = directory
        return

    # pylint: disable=W0612,R0914
    def generate_index(self):
        display_name = escape_html(self.dir_name if self.dir_name else "/")
        html = StringIO()
        html.write(self.header % locals())

        # If this is a subdirectory, create a link back to the parent.
        if self.dir_name:
            parent_dirname = ("/" + self.dir_name).rsplit("/", 1)[0]
            html.write(self.parent_backlink % locals())

        for subdir_name, subdir in sorted(iteritems(self.subdirs)):
            subdir_link = escape_html(url_quote(
                self.dir_name + "/" + subdir_name if self.dir_name
                else subdir_name))
            subdir_name = escape_html(subdir_name)

            html.write(self.subdir_link % locals())

        for filename, key in sorted(iteritems(self.contents)):
            ext = splitext(filename)[-1]
            icon_name = self.icons.get(ext, "binary.png")
            suffix_type = self.suffix_types.get(ext, "   ")
            file_link = escape_html(url_quote(key.name))
            filename = escape_html(filename)
            last_modified = escape_html(key.last_modified)
            size = str(key.size)
            description = ""

            html.write(self.file_link % locals())

        html.write(self.footer % locals())

        return html.getvalue()


class S3StaticWebsiteIndexer(object):
    bucket = "dist.kanga.org"
    profile = None
    region = "us-west-2"


    def __init__(self, region, bucket, profile):
        super(S3StaticWebsiteIndexer, self).__init__()
        self.region = region
        self.bucket = bucket
        self.profile = profile

        self.s3 = boto.s3.connect_to_region(
            self.region, profile_name=self.profile,
            calling_format=OrdinaryCallingFormat())

        self.dirs = {"": Directory("")}

        return

    def generate_indexes(self):
        bucket = self.s3.get_bucket(self.bucket)
        keys = list(bucket.list())

        for key in keys:
            self.add_key_to_index(key)

        for directory in self.dirs.itervalues():
            self.write_directory_index(bucket, directory)

        return

    def add_key_to_index(self, key):
        dir_name, key_basename = split_path(key.name)

        if key_basename == "index.html":
            return

        directory = self.dirs.get(dir_name)
        if directory is None:
            directory = Directory(dir_name)
            self.dirs[dir_name] = directory

        directory.add_content(key)

        # Write a subdirectory entry into each parent directory as needed.
        while dir_name != "":
            parent_dirname, tail = split_path(dir_name)
            parent = self.dirs.get(parent_dirname)

            if parent is None:
                parent = Directory(parent_dirname)
                self.dirs[parent_dirname] = parent

            parent.add_subdir(tail, directory)

            dir_name = parent_dirname
            directory = parent

        return

    @staticmethod
    def write_directory_index(bucket, directory):
        index_html = directory.generate_index()

        if directory.dir_name:
            index_name = directory.dir_name + "/index.html"
        else:
            index_name = "index.html"

        index = bucket.new_key(index_name)
        index.content_type = "text/html"
        index.content_encoding = "UTF-8"
        index.storage_class = "REDUCED_REDUNDANCY"
        index.set_contents_from_string(index_html, policy='public-read',
                                       reduced_redundancy=True)

        print("Uploaded %s" % index.name)
        return

def genindexes():
    region = profile = bucket = None

    try:
        opts, args = getopt(argv[1:], "b:hp:r:", [
            "bucket=", "help", "profile=", "region="])
    except GetoptError as e:
        print(str(e), file=stderr)
        usage()
        return 1

    for opt, value in opts:
        if opt in ("-b", "--bucket"):
            bucket = value
        elif opt in ("-h", "--help"):
            usage(stdout)
            return 0
        elif opt in ("-p", "--profile"):
            profile = value
        elif opt in ("-r", "--region"):
            region = value

    if len(args) > 0:
        print("Unknown argument %r" % args[0], file=stderr)
        return 1

    indexer = S3StaticWebsiteIndexer(region=region, profile=profile,
                                     bucket=bucket)
    indexer.generate_indexes()
    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: kdist-index [options]

Options:
    -b <bucket-name> | --bucket=<bucket-name>
        Generate index.html objects for the specified bucket.
        Defaults to 'dist.kanga.org'.

    -h | --help
        Show this usage information.

    -p <profile-name> | --profile <profile-name>
        Use the specified profile for credentials.

    -r <region> | --region <region>
        The AWS region to connect to.  Defaults to 'us-west-2'.
""")
    fd.flush()
    return
