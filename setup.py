# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from setuptools import find_packages, setup

setup(
    name="aead",
    description="An authenticated encrypted implementation.",
    version="0.1.dev1",
    install_requires=[
        "cryptography"
    ],
    packages=find_packages(exclude=["tests*"]),
    author="Terry Chia",
    author_email="terrycwk1994@gmail.com",
)
