#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
"""Unites routes from compute and consume files."""
# flake8: noqa
from flask import Blueprint

services = Blueprint("services", __name__)

from .compute import *  # isort:skip
from .consume import *  # isort:skip
