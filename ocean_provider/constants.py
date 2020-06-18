#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0


class ConfigSections:
    RESOURCES = 'resources'
    OSMOSIS = 'osmosis'


class BaseURLs:
    BASE_PROVIDER_URL = '/api/v1'
    SWAGGER_URL = '/api/v1/docs'  # URL for exposing Swagger UI (without trailing '/')
    ASSETS_URL = BASE_PROVIDER_URL + '/services'


class Metadata:
    TITLE = 'Provider'
    DESCRIPTION = 'Ocean Provider is the technical component executed by Data Providers allowing them to ' \
                  'provide extended data services. When running with our Docker images, ' \
                  'it is exposed under `http://localhost:8030`.'
    HOST = 'myfancyprovider.com'
