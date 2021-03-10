#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

"""The setup script."""

#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

from setuptools import find_packages, setup

with open("README.md") as readme_file:
    readme = readme_file.read()

# Installed by pip install ocean-provider
# or pip install -e .
install_requirements = [
    # Install ocean-utils first
    "Flask==1.1.2",
    "Flask-Cors==3.0.8",
    "Flask-RESTful==0.3.8",
    "flask-swagger==0.2.14",
    "flask-swagger-ui==3.25.0",
    "Jinja2>=2.10.1",
    "gunicorn==20.0.4",
    "osmosis-azure-driver==0.1.0",
    "osmosis-aws-driver==0.1.0",
    "osmosis-driver-interface==0.1.0",
    "osmosis-on-premise-driver==0.1.0",
    "osmosis-ipfs-driver==0.1.0",
    "Werkzeug>=0.15.3",
    "ocean-lib>=0.5.6",
    "requests_testadapter",
    "eciespy",
    "coincurve>=13,<15",
    "ipaddress",
    "dnspython",
    "flask-sieve==1.2.2",
    "SQLAlchemy==1.3.23",
]

# Required to run setup.py:
setup_requirements = ["pytest-runner"]

test_requirements = [
    "codacy-coverage",
    "coverage",
    "docker",
    "mccabe",
    "pylint",
    "pytest",
    "pytest-watch",
    "tox",
    "plecos",
]

# Possibly required by developers of ocean-provider:
dev_requirements = [
    "bumpversion",
    "pkginfo",
    "twine",
    "watchdog",
    "python-dotenv==0.15.0",
    "flake8",
    "isort",
    "black",
    "pre-commit",
    "licenseheaders",
]

setup(
    author="leucothia",
    author_email="devops@oceanprotocol.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.8",
    ],
    description="🐳 Ocean Provider.",
    extras_require={
        "test": test_requirements,
        "dev": dev_requirements + test_requirements,
    },
    install_requires=install_requirements,
    license="Apache Software License 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords="ocean-provider",
    name="ocean-provider",
    packages=find_packages(
        include=["ocean_provider", "ocean_provider.utils", "ocean_provider.app"]
    ),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/oceanprotocol/provider-py",
    # fmt: off
    # bumpversion needs single quotes
    version='0.4.6',
    # fmt: on
    zip_safe=False,
)
