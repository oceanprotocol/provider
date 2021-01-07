#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import configparser

from flask import jsonify, url_for
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

from ocean_provider.config import Config
from ocean_provider.constants import BaseURLs, ConfigSections, Metadata
from ocean_provider.myapp import app
from ocean_provider.routes import services
from ocean_provider.utils.basics import get_provider_wallet

config = Config(filename=app.config['CONFIG_FILE'])
provider_url = config.get(ConfigSections.RESOURCES, 'ocean_provider.url')


def get_version():
    conf = configparser.ConfigParser()
    conf.read('.bumpversion.cfg')
    return conf['bumpversion']['current_version']


@app.route("/")
def version():
    """
    Created a global dictionary
    to store the services' routes.
    It is open for modifications, by simply adding the service
    name and the url for it.    """

    info = dict()
    info['software'] = Metadata.TITLE
    info['version'] = get_version()
    info['network-url'] = config.network_url
    info['provider-address'] = get_provider_wallet().address
    # Added the expose endpoint. Here are the URLs to the
    # existed endpoints. Check test_compute.py, in function
    # test_compute_expose_endpoint.
    info['servicesEndpoints'] = {
        "access": url_for('services.download'),
        "compute": url_for('services.compute_get_status_job'),
        "nonce": url_for('services.get_user_nonce'),
        "encrypt": url_for('services.encrypt'),
        "initialize": url_for('services.initialize'),
    }
    return jsonify(info)


@app.route("/spec")
def spec():
    swag = swagger(app)
    swag['info']['version'] = get_version()
    swag['info']['title'] = Metadata.TITLE
    swag['info']['description'] = Metadata.DESCRIPTION
    return jsonify(swag)


# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    BaseURLs.SWAGGER_URL,
    provider_url + '/spec',
    config={  # Swagger UI config overrides
        'app_name': "Test application"
    },
)

# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint, url_prefix=BaseURLs.SWAGGER_URL)
app.register_blueprint(services, url_prefix=BaseURLs.ASSETS_URL)

if __name__ == '__main__':
    app.run(port=8030)
