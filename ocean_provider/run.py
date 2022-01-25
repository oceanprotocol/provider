#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import configparser
import logging
from http.client import responses

from flask import jsonify, request
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint
from ocean_provider.config import Config
from ocean_provider.constants import BaseURLs, ConfigSections, Metadata
from ocean_provider.log import setup_logging
from ocean_provider.myapp import app
from ocean_provider.routes import services
from ocean_provider.utils.basics import get_provider_wallet, get_web3
from ocean_provider.utils.util import get_compute_info

setup_logging()
config = Config(filename=app.config["PROVIDER_CONFIG_FILE"])
provider_url = config.get(ConfigSections.RESOURCES, "ocean_provider.url")

logger = logging.getLogger(__name__)


@app.before_request
def log_incoming_request():
    logger.info(f"{request}")


def get_services_endpoints():
    services_endpoints = dict(
        map(
            lambda url: (url.endpoint.replace("services.", ""), url),
            filter(
                lambda url: url.endpoint.startswith("services."),
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
        the existing endpoints from routes.py.
    """
    logger.info("root endpoint called")
    info = dict()
    info["software"] = Metadata.TITLE
    info["version"] = get_version()

    chain_id = app.config.get("chain_id")
    if not chain_id:
        logger.debug("get chain_id from node")
        chain_id = get_web3().eth.chain_id
        app.config["chain_id"] = chain_id

    info["chainId"] = chain_id
    info["providerAddress"] = get_provider_address()
    info["serviceEndpoints"] = get_services_endpoints()
    info["computeAddress"], info["computeLimits"] = get_compute_info()
    response = jsonify(info)
    logger.debug(f"root endpoint response = {response}")
    return response


@app.route("/spec")
def spec():
    logger.info("spec endpoint called")
    swag = swagger(app)
    swag["info"]["version"] = get_version()
    swag["info"]["title"] = Metadata.TITLE
    swag["info"]["description"] = Metadata.DESCRIPTION
    response = jsonify(swag)
    logger.debug(f"spec endpoint response = {response}")
    return responses


# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    BaseURLs.SWAGGER_URL,
    provider_url + "/spec",
    config={"app_name": "Test application"},  # Swagger UI config overrides
)

# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint, url_prefix=BaseURLs.SWAGGER_URL)
app.register_blueprint(services, url_prefix=BaseURLs.SERVICES_URL)

if __name__ == "__main__":
    app.run(port=8030)
