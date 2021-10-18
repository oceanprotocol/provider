#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#


from enum import Enum


class ConsumableCodes(Enum):
    """
    Contains constant values for:
     - OK
     - ASSET_DISABLED
     - CONNECTIVITY_FAIL
     - CREDENTIAL_NOT_IN_ALLOW_LIST
     - CREDENTIAL_IN_DENY_LIST
    """

    OK = 0
    ASSET_DISABLED = 1
    CONNECTIVITY_FAIL = 2
    CREDENTIAL_NOT_IN_ALLOW_LIST = 3
    CREDENTIAL_IN_DENY_LIST = 4


class MalformedCredential(Exception):
    pass
