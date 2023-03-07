import os
from typing import List
from urllib.parse import urljoin


from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.address import get_provider_fee_token
from ocean_provider.utils.basics import get_config, get_web3


requests_session = get_requests_session()


def get_compute_environments_endpoint():
    print(
        f"op serv local: {get_config().operator_service_url}\n,"
        f"urljoin result: {urljoin(get_config().operator_service_url, 'api/v1/operator/environments')}"
    )
    return urljoin(get_config().operator_service_url, "api/v1/operator/environments")


def get_c2d_environments() -> List:
    if not os.getenv("OPERATOR_SERVICE_URL"):
        return []

    standard_headers = {"Content-Type": "application/json", "Connection": "close"}
    web3 = get_web3()
    params = dict({"chainId": web3.eth.chain_id})
    response = requests_session.get(
        get_compute_environments_endpoint(), headers=standard_headers, params=params
    )

    # loop envs and add provider token from config
    envs = response.json()
    for env in envs:
        env["feeToken"] = get_provider_fee_token(web3.eth.chain_id)

    return envs


def check_environment_exists(envs, env_id):
    """Checks if environment with id exists in environments list."""
    return bool(get_environment(envs, env_id))


def get_environment(envs, env_id):
    """Gets environment with id exists in environments list."""
    if not envs or not isinstance(envs, list):
        return False

    matching_envs = [env for env in envs if env["id"] == env_id]
    return matching_envs[0] if len(matching_envs) > 0 else None
