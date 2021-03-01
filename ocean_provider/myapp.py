#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

# fmt: off
import os
import sqlite3
from os.path import abspath, dirname
from flask import Flask
from flask_cors import CORS
from flask_sieve import Sieve
from ocean_provider.utils.basics import get_config

app = Flask(__name__)
CORS(app)
Sieve(app)

if "CONFIG_FILE" in os.environ and os.environ["CONFIG_FILE"]:
    app.config["CONFIG_FILE"] = os.environ["CONFIG_FILE"]
else:
    app.config["CONFIG_FILE"] = "config.ini"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

PROJECT_ROOT = dirname(dirname(abspath(__file__)))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////" + os.path.join(
    PROJECT_ROOT, "db", get_config().storage_path
)

from ocean_provider.models import db as db_models  # noqa isort: skip
db = db_models

try:
    db.create_all()
except sqlite3.OperationalError:
    pass
# fmt: on
