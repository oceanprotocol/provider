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
    # "ocean-contracts==1.0.0a1",
    "web3==5.25.0",
    "Flask==1.1.2",
    "itsdangerous==2.0.1",  # Required to use Flask 1.1.2. https://serverfault.com/a/1094095
    "Flask-Cors==3.0.9",
    "flask_caching==1.10.1",
    "Flask-RESTful==0.3.8",
    "flask-swagger==0.2.14",
    "flask-swagger-ui==3.25.0",
    "Jinja2>=2.10.1,<3.1",
    "gunicorn==20.0.4",
    "ocean-contracts==1.0.0a31",
    "coloredlogs==15.0.1",
    "Werkzeug==0.16.1",
    "requests_testadapter",
    "eciespy",
    "coincurve>=13,<15",
    "ipaddress",
    "dnspython",
    "flask-sieve==1.3.1",
    "SQLAlchemy==1.3.23",
    "json-sempai==0.4.0",
    "redis==4.0.2",
]

# Required to run setup.py:
setup_requirements = ["pytest-runner"]

test_requirements = [
    "codacy-coverage",
    "coverage",
    "docker",
    "freezegun==1.1.0",
    "mccabe",
    "pylint",
    "pytest",
    "pytest-watch",
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
    "black==22.1.0",
    "pre-commit",
    "licenseheaders",
    "pytest-env",
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
    version='1.0.5',
    # fmt: on
    zip_safe=False,
)
