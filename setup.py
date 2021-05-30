#!/usr/bin/env python

# Minimal setup.py for compatibility with
# https://docs.openstack.org/pbr/latest/user/using.html

from setuptools import setup

setup(
    setup_requires=["pbr"],
    pbr=True,
)
