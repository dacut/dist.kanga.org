#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from os import listdir, makedirs
from os.path import basename, exists
from shutil import rmtree
from sys import exit
from tempfile import mkdtemp
from .distribution import Distribution
from .logging import log
from .platform import invoke

class Repository(Distribution):
    s3_region = "us-west-2"
    bucket_name = "dist.kanga.org"

    def __init__(self):
        super(Repository, self).__init__()
        self.tempdir = mkdtemp()
        self.s3 = boto.s3.connect_to_region(
            self.s3_region, calling_format=OrdinaryCallingFormat())
        self.bucket = self.s3.get_bucket(self.bucket_name)
        return

    def __del__(self):
        #rmtree(self.tempdir)
        return

    def download_contents(self):
        log.info("Downloading existing contents from %s",
                 self.dist_prefix)
        for key in self.bucket.list(prefix=self.dist_prefix):
            filename = key.name[len(self.dist_prefix):]

            if basename(filename) == "index.html":
                continue

            dirname = filename.rsplit("/", 1)[0]
            if not exists(self.tempdir + "/" + dirname):
                makedirs(self.tempdir + "/" + dirname)

            key.get_contents_to_filename(self.tempdir + "/" + filename)

        log.info("Download completed")
        return

    def update_repo_database(self):
        log.info("Updating repository database")
        invoke("createrepo",
               "--baseurl", "https://dist.kanga.org/" + self.dist_prefix,
               "--excludes", "index.html",
               "--retain-old-md", "5",
               "--distro", self.dist_suffix,
               self.tempdir)
        log.info("Repository database updated")
        return

    def upload_repo_database(self):
        log.info("Uploading repository database")
        for filename in listdir(self.tempdir + "/repodata"):
            key = self.bucket.new_key(
                self.dist_prefix + "repodata/" + filename)
            log.debug("Uploading %s", key.name)
            key.set_contents_from_filename(
                self.tempdir + "/repodata/" + filename,
                reduced_redundancy=True, policy='public-read')
        log.info("Repository database upload completed")
        return
        
def repoupdate():
    log.info("Invoking repoupdate")
    try:
        repo = Repository()
        repo.download_contents()
        repo.update_repo_database()
        repo.upload_repo_database()
    except Exception as e:
        log.error("repoupdate failed", exc_info=True)
        return 1
    else:
        log.info("repoupdate succeeded")
        return 0

