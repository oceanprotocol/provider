"""Unites routes from compute and consume files."""
# flake8: noqa
from flask import Blueprint

from .compute import *  # isort:skip
from .consume import *  # isort:skip

services = Blueprint("services", __name__)
