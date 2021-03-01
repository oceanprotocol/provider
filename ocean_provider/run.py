#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import configparser

from flask import jsonify
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint
from ocean_provider.config import Config
from ocean_provider.constants import BaseURLs, ConfigSections, Metadata
from ocean_provider.myapp import app
from ocean_provider.routes import services
from ocean_provider.util import get_compute_address
from ocean_provider.utils.basics import get_provider_wallet

config = Config(filename=app.config["CONFIG_FILE"])
provider_url = config.get(ConfigSections.RESOURCES, "ocean_provider.url")
# not included URLs
blocked_url = ["services.simple_flow_consume"]


def get_services_endpoints():
    services_endpoints = dict(
        map(
            lambda url: (url.endpoint.replace("services.", ""), url),
            filter(
                lambda url: url.endpoint.startswith("services.")
                and url.endpoint not in blocked_url,
                app.url_map.iter_rules(),
            ),
        )
    )
    for (key, value) in services_endpoints.items():
        services_endpoints[key] = (
            list(
                map(
                    str,
                    filter(
                        lambda method: str(method) not in ["OPTIONS", "HEAD"],
                        value.methods,
                    ),
                )
            )[0],
            str(value),
        )
    return services_endpoints


def get_provider_address():
    """Gets the provider wallet address."""
    provider_address = get_provider_wallet().address
    return provider_address


def get_version():
    conf = configparser.ConfigParser()
    conf.read(".bumpversion.cfg")
    return conf["bumpversion"]["current_version"]


@app.route("/")
def version():
    """
    Contains the provider data for an user:
        - software;
        - version;
        - network url;
        - provider address;
        - service endpoints, which has all
        the existing endpoints from routes.py
        which are not in blocked_url.
    """

    info = dict()
    info["software"] = Metadata.TITLE
    info["version"] = get_version()
    info["network-url"] = config.network_url
    info["providerAddress"] = get_provider_address()
    info["computeAddress"] = get_compute_address()
    info["serviceEndpoints"] = get_services_endpoints()
    return jsonify(info)


@app.route("/spec")
def spec():
    swag = swagger(app)
    swag["info"]["version"] = get_version()
    swag["info"]["title"] = Metadata.TITLE
    swag["info"]["description"] = Metadata.DESCRIPTION
    return jsonify(swag)


# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    BaseURLs.SWAGGER_URL,
    provider_url + "/spec",
    config={"app_name": "Test application"},  # Swagger UI config overrides
)

# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint, url_prefix=BaseURLs.SWAGGER_URL)
app.register_blueprint(services, url_prefix=BaseURLs.ASSETS_URL)

if __name__ == "__main__":
    app.run(port=8030)
