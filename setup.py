#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import logging
from os import listdir
from setuptools import setup

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

kdist_files = (
    ["kdist/" + f for f in listdir("kdist")
     if f.endswith(".csv")] +
    ["kdist/SPECS/" + f for f in listdir("kdist/SPECS")
     if f.endswith(".in")]
)

setup(
    name="dist.kanga.org",
    version="1.0",
    packages=['kdist'],
    package_data={
        'kdist': kdist_files,
    },
    entry_points={
        "console_scripts": [
            "kdist-genindexes=kdist.index:genindexes",
            "kdist-localbuild=kdist.package:localbuild",
            "kdist-repoupdate=kdist.repository:repoupdate",
            "kdist-remotebuild=kdist.remote:remotebuild",
            "kdist-server=kdist.server:run_server",
        ]
    },
    install_requires=["boto3>=1.0", "Flask>=0.10", "pycrypto>=2.6", "six>=1.10"],
    setup_requires=["nose>=1.0"],

    # PyPI information
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    description="Utilities for publishing to YUM repositories",
    license="BSD",
    url="https://github.com/dacut/dist.kanga.org",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords=['repository', 'distribution', 'yum'],
    zip_safe=False,
)
