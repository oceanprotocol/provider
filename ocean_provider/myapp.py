#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

"""
This module creates an instance of flask `app`, creates `user_nonce` table if not exists, and sets the environment configuration.
If `PROVIDER_CONFIG_FILE` is not found in environment variables, default `config.ini` file is used.
"""

from flask import Flask, _app_ctx_stack
from flask_cors import CORS
from flask_sieve import Sieve
from ocean_provider.log import setup_logging
from sqlalchemy.orm import scoped_session

from .database import Base, SessionLocal, engine

setup_logging()

with engine.connect() as con:
    rs = con.execute(
        """
        CREATE TABLE IF NOT EXISTS user_nonce (
          address VARCHAR(255) NOT NULL,
          nonce VARCHAR(255) NOT NULL,
          PRIMARY KEY (address)
        )
        """
    )

    rs = con.execute(
        """
        CREATE TABLE IF NOT EXISTS revoked_tokens (
          token VARCHAR(255) NOT NULL,
          PRIMARY KEY (token)
        )
        """
    )

app = Flask(__name__)
CORS(app)
Sieve(app)
app.session = scoped_session(SessionLocal, scopefunc=_app_ctx_stack.__ident_func__)
Base.query = app.session.query_property()
