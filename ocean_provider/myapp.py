#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import os
from os.path import abspath, dirname

from flask import Flask
from flask_cors import CORS
from flask_sieve import Sieve
from flask_sqlalchemy import SQLAlchemy

from ocean_provider.utils.basics import get_config

app = Flask(__name__)
CORS(app)
Sieve(app)

if 'CONFIG_FILE' in os.environ and os.environ['CONFIG_FILE']:
    app.config['CONFIG_FILE'] = os.environ['CONFIG_FILE']
else:
    app.config['CONFIG_FILE'] = 'config.ini'


PROJECT_ROOT = dirname(dirname(abspath(__file__)))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////' + os.path.join(
    PROJECT_ROOT,
    get_config().storage_path
)

db = SQLAlchemy(app)


class AccessToken(db.Model):
    __tablename__ = 'access_token'

    access_token = db.Column(
        db.String(255), nullable=False, primary_key=True, autoincrement=False
    )
    consumer_address = db.Column(db.String(255), nullable=False)
    delegate_address = db.Column(db.String(255), nullable=False)
    did = db.Column(db.String(255), nullable=False)
    tx_id = db.Column(db.String(255), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)


class UserNonce(db.Model):
    __tablename__ = 'user_nonce'
    FIRST_NONCE = 0

    address = db.Column(
        db.String(255), nullable=False, primary_key=True, autoincrement=False
    )
    nonce = db.Column(db.String(255), nullable=False)


db.create_all()
