#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from boto.s3.key import Key
from cgi import escape as escape_html
from six.moves import cStringIO as StringIO
from six.moves.html_entities import entitydefs
from six.moves.urllib.parse import quote as url_quote
from getopt import getopt, GetoptError
from os.path import split as split_path, splitext
from sys import argv, exit, stderr, stdout

s3 = None
suffixtype = {
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

def main(args):
    global s3
    bucket = "dist.kanga.org"
    profile = None
    region = "us-west-2"

    try:
        opts, args = getopt(args, "b:hp:r:", [
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

    s3 = boto.s3.connect_to_region(
        region, profile_name=profile, calling_format=OrdinaryCallingFormat())
    generate_indexes(bucket)
    return 0

def generate_indexes(bucket_name):
    bucket = s3.get_bucket(bucket_name)
    keys = list(bucket.list())
    dirs = {}
    subdirs = {}

    for key in keys:
        dir_name, key_basename = split_path(key.name)

        if key_basename == "index.html":
            continue

        dir_contents = dirs.get(dir_name)
        if dir_contents is None:
            dir_contents = {}
            dirs[dir_name] = dir_contents

        dir_contents[key_basename] = key

        # Write a subdirectory entry into the parent directory if needed.
        while dir_name != "":
            parent_dir, tail = split_path(dir_name)
            parent_contents = subdirs.get(parent_dir)
            
            if parent_contents is None:
                parent_contents = set()
                subdirs[parent_dir] = parent_contents
            
            if tail in parent_contents:
                # Already have an entry for the subdir
                break

            parent_contents.add(tail)
            dir_name = parent_dir

    all_dirs = set(dirs.keys()) ^ set(subdirs.keys())

    for dir_name in sorted(all_dirs):
        display_name = dir_name if dir_name else "/"

        html = StringIO()
        html.write("<DOCTYPE html>\n"
                   "<html>\n"
                   "  <head>\n"
                   "    <title>Index of ")
        html.write(escape_html(display_name))
        html.write('</title>\n'
                   '  </head>\n'
                   '  <body>\n'
                   '    <table>\n'
                   '      <tr><th valign="top">&nbsp;</th>'
                   '<th>Name</th><th>Last modified</th><th>Size</th>'
                   '<th>Description</th></tr>\n')

        if dir_name:
            parent = ("/" + dir_name).rsplit("/", 1)[0]
            html.write('    <tr><td valign="top"><img src="/icons/back.gif"'
                       ' alt="DIR"></td><td><a href="%s/index.html">'
                       'Parent Directory</a></td><td>&nbsp;</td><td>-</td>'
                       '<td>&nbsp;</td></tr>\n' % escape_html(parent))

        for subdir in sorted(subdirs.get(dir_name, [])):
            html.write('      <tr><td valign="top"><img src="/icons/'
                       'folder.gif" alt="[DIR]"></td><td><a href="/')
            if dir_name:
                html.write(escape_html(url_quote(dir_name + "/" + subdir)))
            else:
                html.write(escape_html(subdir))
            html.write('/index.html">')
            html.write(escape_html(subdir))
            html.write('</a></td><td>&nbsp;</td><td>-</td><td>&nbsp;</td>'
                       '</tr>\n')

        subkeys = dirs.get(dir_name, {})
        file_names = sorted(subkeys.keys())

        for name in file_names:
            ext = splitext(name)[1]

            key = subkeys[name]
            html.write('      <tr><td valign="top"><img src="/icons/')
            html.write(icons.get(ext, "binary.png"))
            html.write('" alt="[')
            html.write(suffixtype.get(ext, "   "))
            html.write(']"></td><td><a href="/')
            html.write(escape_html(url_quote(key.name)))
            html.write('">')
            html.write(escape_html(name))
            html.write('</td><td>')
            html.write(escape_html(key.last_modified))
            html.write('</td><td>')
            html.write(str(key.size))
            html.write('</td></tr>\n')

        html.write('    </table>\n'
                   '  </body>\n'
                   '</html>\n')
        
        if dir_name:
            index_name = dir_name + "/index.html"
        else:
            index_name = "index.html"

        index = bucket.new_key(index_name)
        index.content_type = "text/html"
        index.content_encoding = "UTF-8"
        index.storage_class = "REDUCED_REDUNDANCY"
        index.set_contents_from_string(html.getvalue(), policy='public-read',
                                       reduced_redundancy=True)
        print("Uploaded %s" % index.name)
                       
    return

def usage(fd=stderr):
    fd.write("""\
Usage: distindex.py [options]

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

if __name__ == "__main__":
    exit(main(argv[1:]))
