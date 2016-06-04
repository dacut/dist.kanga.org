#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from kdist.platform import get_os_version

class Distribution(object):
    """
    Mixin class for providing objects with distribution-related resources.
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
            "default": ".amzn1",
        },
    }

    rolling_release_dists = { "amzn" }

    def __init__(self, s3_region=None, bucket_name=None):
        super(Distribution, self).__init__()
        self.s3_region = (
            s3_region if s3_region else Distribution.s3_region)
        self.bucket_name = (
            bucket_name if bucket_name else Distribution.bucket_name)

        self.linux_dist, self.dist_version = get_os_version()
        self.os_prefix = self.os_prefixes[self.linux_dist] + "/"
        if self.linux_dist in self.rolling_release_dists:
            # On rolling release OSes, it doesn't make as much sense to include
            # the version in the dist_prefix.
            self.dist_prefix = self.os_prefix
        else:
            self.dist_prefix = self.os_prefix + self.dist_version + "/"
        suffixes = self.dist_suffixes[self.linux_dist]

        if self.dist_version in suffixes:
            self.dist_suffix = suffixes[self.dist_version]
        else:
            self.dist_suffix = suffixes["default"]

        return


# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
