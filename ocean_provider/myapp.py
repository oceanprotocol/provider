#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import os

from flask import Flask, _app_ctx_stack
from flask_cors import CORS
from flask_sieve import Sieve
from sqlalchemy.orm import scoped_session

from .database import Base, SessionLocal, engine

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

app = Flask(__name__)
CORS(app)
Sieve(app)
app.session = scoped_session(SessionLocal, scopefunc=_app_ctx_stack.__ident_func__)
Base.query = app.session.query_property()

if "CONFIG_FILE" in os.environ and os.environ["CONFIG_FILE"]:
    app.config["CONFIG_FILE"] = os.environ["CONFIG_FILE"]
else:
    app.config["CONFIG_FILE"] = "config.ini"
