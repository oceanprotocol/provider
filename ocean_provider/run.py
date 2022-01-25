#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from flask_swagger_ui import get_swaggerui_blueprint
from ocean_provider.config import Config
from ocean_provider.constants import BaseURLs, ConfigSections
from ocean_provider.log import setup_logging
from ocean_provider.myapp import app
from ocean_provider.routes import services

setup_logging()
config = Config(filename=app.config["PROVIDER_CONFIG_FILE"])
provider_url = config.get(ConfigSections.RESOURCES, "ocean_provider.url")

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
