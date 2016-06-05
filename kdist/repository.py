#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto3
from os import listdir, makedirs
from os.path import basename, exists
from shutil import rmtree
from sys import exit
from tempfile import mkdtemp
from .distribution import Distribution
from .logging import log
from .platform import invoke
from .s3 import get_object_to_file

PUBLIC_READ = "public-read"
REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"

class Repository(Distribution):
    s3_region = "us-west-2"
    bucket_name = "dist.kanga.org"

    def __init__(self):
        super(Repository, self).__init__()
        self.tempdir = mkdtemp(prefix="rpmrepo.")
        self.s3 = boto3.client("s3", region_name=self.s3_region)
        self.bucket_name = self.bucket_name
        self.old_repodata = set()
        return

    def __del__(self):
        rmtree(self.tempdir)
        return

    def download_contents(self):
        log.info("Downloading existing contents from %s",
                 self.dist_prefix)

        list_kw = {"Bucket": self.bucket_name, "Prefix": self.dist_prefix}
        while True:
            response = self.s3.list_objects_v2(**list_kw)

            for s3obj in response["Contents"]:
                key = s3obj["Key"]
                filename = key[len(self.dist_prefix):]

                if basename(filename) == "index.html":
                    continue

                dirname = filename.rsplit("/", 1)[0]

                if dirname == "repodata":
                    # Delete old repository data after the fact.
                    self.old_repodata.add(filename)
                else:
                    if not exists(self.tempdir + "/" + dirname):
                        makedirs(self.tempdir + "/" + dirname)

                    log.debug("Downloading %r", filename)

                    get_object_to_file(
                        self.s3, Bucket=self.bucket_name, Key=key,
                        File=self.tempdir + "/" + filename)

                    log.info("Download completed")

            if not response["IsTruncated"]:
                break

            list_kw["ContinuationToken"] = response["NextContinuationToken"]
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
            filename = "repodata/" + filename
            key = self.dist_prefix + filename
            log.info("Uploading %s", key)

            with open(self.tempdir + "/" + filename, "r") as ifd:
                self.s3.put_object(
                    ACL=PUBLIC_READ, Body=ifd, Bucket=self.bucket_name,
                    Key=key, StorageClass=REDUCED_REDUNDANCY)
                if filename in self.old_repodata:
                    log.debug("Upload was replacment: %s", filename)
                    self.old_repodata.remove(filename)

        for filename in self.old_repodata:
            key = self.dist_prefix + filename
            log.info("Deleting %s", key)
            self.s3.delete_object(Bucket=self.bucket_name, Key=key)

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

