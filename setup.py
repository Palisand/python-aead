from __future__ import absolute_import, division, print_function

from setuptools import setup, find_packages

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
