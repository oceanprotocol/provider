import os
from urllib.parse import urljoin

from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.address import get_provider_fee_token
from ocean_provider.utils.basics import get_configured_chains

requests_session = get_requests_session()


def get_compute_environments_endpoint():
    return urljoin(os.getenv("OPERATOR_SERVICE_URL"), "api/v1/operator/environments")


def get_c2d_environments(flat=False):
    if not os.getenv("OPERATOR_SERVICE_URL"):
        return []

    standard_headers = {"Content-type": "application/json", "Connection": "close"}
    all_environments = [] if flat else {}

    for chain in get_configured_chains():
        params = {"chainId": chain}
        response = requests_session.get(
            get_compute_environments_endpoint(), headers=standard_headers, params=params
        )

        # add provider token from config
        envs = response.json()
        for env in envs:
            env["feeToken"] = get_provider_fee_token(chain)

        if flat:
            all_environments.extend(envs)
        else:
            all_environments[chain] = envs

    return all_environments


def check_environment_exists(envs, env_id):
    """Checks if environment with id exists in environments list."""
    return bool(get_environment(envs, env_id))


def get_environment(envs, env_id):
    """Gets environment with id exists in environments list."""
    if not envs or not isinstance(envs, list):
        return False

    matching_envs = [env for env in envs if env["id"] == env_id]
    return matching_envs[0] if len(matching_envs) > 0 else None
