from setuptools import setup

setup(
    name="dist.kanga.org",
    version="1.0",
    description="Utilities for publishing to dist.kanga.org",
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    packages=['kdist'],
    entry_points=dict(
        console_scripts=[
            "kdist-genindexes=kdist.index:genindexes",
            "kdist-localbuild=kdist.package:localbuild",
            "kdist-repoupdate=kdist.repository:repoupdate",
        ]
    ),
)
