#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#


class InvalidSignatureError(Exception):
    """User signature is not valid."""


class RequestNotFound(Exception):
    """Request undeclared/undefined."""
