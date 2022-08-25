#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import requests

logger = logging.getLogger(__name__)


def validate_docker(container):
    # Validate `container` data
    for key in ["entrypoint", "image", "checksum"]:
        if not container.get(key):
            return False, "missing_entrypoint_image_checksum"

    if not container["checksum"].startswith("sha256:"):
        return False, "checksum_prefix"

    try:
        container_image = (
            container["image"]
            if "/" in container["image"]
            else f"library/{container['image']}"
        )
        ns_string = container_image.replace("/", "/repositories/")
        dh_response = requests.get(
            f"http://hub.docker.com/v2/namespaces/{ns_string}/tags/{container['tag']}/images"
        )
        digests = [item["digest"].lower() for item in dh_response.json()]
        assert container["checksum"].lower() in digests
    except Exception:
        return False, "invalid"

    return True, ""
