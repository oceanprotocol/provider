#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#


class ConfigSections:
    """
    This class stores values for:

    - `RESOURCES`
    - `OSMOSIS`
    """

    RESOURCES = "resources"
    OSMOSIS = "osmosis"


class BaseURLs:
    """
    This class stores values for:

    - `BASE_PROVIDER_URL`
    - `SWAGGER_URL`
    - `ASSETS_URL`
    """

    BASE_PROVIDER_URL = "/api/v1"
    SWAGGER_URL = "/api/v1/docs"  # URL for exposing Swagger UI (without trailing '/')
    ASSETS_URL = BASE_PROVIDER_URL + "/services"


class Metadata:
    """
    This class stores values for:

    - `TITLE`
    - `DESCRIPTION`
    """

    TITLE = "Provider"
    DESCRIPTION = (
        "Ocean Provider is the technical component executed by Data Providers allowing them to "
        "provide extended data services. When running with our Docker images, "
        "it is exposed under `http://localhost:8030`."
    )
    HOST = "myfancyprovider.com"


class ServiceTypesIndices:
    DEFAULT_METADATA_INDEX = 0
    DEFAULT_PROVENANCE_INDEX = 1
    DEFAULT_AUTHORIZATION_INDEX = 2
    DEFAULT_ACCESS_INDEX = 3
    DEFAULT_COMPUTING_INDEX = 4
