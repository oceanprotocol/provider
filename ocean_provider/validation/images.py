#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

logger = logging.getLogger(__name__)


def validate_container(container):
    # Validate `container` data
    for key in ["entrypoint", "image", "checksum"]:
        if not container.get(key):
            return False, "missing_entrypoint_image_checksum"

    if not container["checksum"].startswith("sha256:"):
        return False, "checksum_prefix"

    return True, ""
