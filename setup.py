#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.md') as history_file:
    history = history_file.read()

# Installed by pip install ocean-provider
# or pip install -e .
install_requirements = [
    # Install ocean-utils first
    'ocean-utils==0.3.7',  # gets PyYAML, coloredlogs, web3
    'ocean-keeper==0.3.5',
    'eciespy==0.3.6',
    'Flask==1.1.2',
    'Flask-Cors==3.0.8',
    'Flask-RESTful==0.3.8',
    'flask-swagger==0.2.14',
    'flask-swagger-ui==3.25.0',
    'Jinja2>=2.10.1',
    'requests>=2.21.0',
    'gunicorn==20.0.4',
    'osmosis-azure-driver==0.0.4',
    'osmosis-aws-driver==0.0.4',
    'osmosis-driver-interface==0.0.7',
    'osmosis-on-premise-driver==0.0.6',
    'osmosis-ipfs-driver==0.0.1',
    'Werkzeug>=0.15.3',
    'web3==4.5.0',
    'requests_testadapter'
]

# Required to run setup.py:
setup_requirements = ['pytest-runner', ]

test_requirements = [
    'codacy-coverage',
    'coverage',
    'docker',
    'mccabe',
    'pylint',
    'pytest',
    'pytest-watch',
    'tox',
    'plecos'
]

# Possibly required by developers of ocean-provider:
dev_requirements = [
    'bumpversion',
    'pkginfo',
    'twine',
    'watchdog',
]

setup(
    author="leucothia",
    author_email='devops@oceanprotocol.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description="🐳 Ocean Provider.",
    extras_require={
        'test': test_requirements,
        'dev': dev_requirements + test_requirements,
    },
    install_requires=install_requirements,
    license="Apache Software License 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords='ocean-provider',
    name='ocean-provider',
    packages=find_packages(include=['ocean_provider', 'ocean_provider.app']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/oceanprotocol/provider-py',
    version='0.1.0',
    zip_safe=False,
)
