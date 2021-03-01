#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from flask_sqlalchemy import SQLAlchemy
from ocean_provider.myapp import app

db = SQLAlchemy(app)


class UserNonce(db.Model):
    __tablename__ = "user_nonce"
    FIRST_NONCE = 0

    address = db.Column(
        db.String(255), nullable=False, primary_key=True, autoincrement=False
    )
    nonce = db.Column(db.String(255), nullable=False)
