#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#


class ConfigSections:
    """
    This class stores values for:

    - `RESOURCES`
    """

    RESOURCES = "resources"


class BaseURLs:
    """
    This class stores values for:

    - `BASE_PROVIDER_URL`
    - `SWAGGER_URL`
    - `SERVICES_URL`
    """

    BASE_PROVIDER_URL = "/api"
    SWAGGER_URL = "/api/docs"  # URL for exposing Swagger UI (without trailing '/')
    SERVICES_URL = BASE_PROVIDER_URL + "/services"


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
