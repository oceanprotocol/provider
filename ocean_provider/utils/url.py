#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import ipaddress
import logging
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from ocean_provider.utils.basics import bool_value_of_env, get_provider_wallet

logger = logging.getLogger(__name__)


def get_redirect(url, redirect_count=0):
    if not is_url(url):
        return None

    if redirect_count > 5:
        logger.info(f"More than 5 redirects for url {url}. Aborting.")

        return None
    try:
        result = requests.head(url, allow_redirects=False)
    except Exception:
        return None
    if result.status_code == 405:
        # HEAD not allowed, so defaulting to get
        try:
            result = requests.get(url, allow_redirects=False)
        except Exception:
            return None

    if result.is_redirect:
        location = urljoin(
            url if url.endswith("/") else f"{url}/", result.headers["Location"]
        )
        logger.info(f"Redirecting for url {url} to location {location}.")

        return get_redirect(location, redirect_count + 1)

    return url


def is_safe_url(url):
    url = get_redirect(url)

    if not url:
        return False

    result = urlparse(url)

    return is_safe_domain(result.hostname)


def is_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:  # noqa
        return False


def is_ip(address):
    return address.replace(".", "").isnumeric()


def is_this_same_provider(url):
    result = urlparse(url)
    try:
        provider_info = requests.get(f"{result.scheme}://{result.netloc}/").json()
        address = provider_info["providerAddress"]
    except (requests.exceptions.RequestException, KeyError):
        address = None

    return address and address.lower() == get_provider_wallet().address.lower()


def _get_records(domain, record_type):
    DNS_RESOLVER = dns.resolver.Resolver()
    try:
        return DNS_RESOLVER.resolve(domain, record_type, search=True)
    except Exception as e:
        logger.info(f"[i] Cannot get {record_type} record for domain {domain}: {e}\n")

        return None


def is_safe_domain(domain):
    ip_v4_records = _get_records(domain, "A")
    ip_v6_records = _get_records(domain, "AAAA")

    result = validate_dns_records(domain, ip_v4_records, "A") and validate_dns_records(
        domain, ip_v6_records, "AAAA"
    )

    if not is_ip(domain):
        return result

    return result and validate_dns_record(domain, domain, "")


def validate_dns_records(domain, records, record_type):
    """
    Verify if all DNS records resolve to public IP addresses.
    Return True if they do, False if any error has been detected.
    """
    if records is None:
        return True

    for record in records:
        if not validate_dns_record(record, domain, record_type):
            return False

    return True


def validate_dns_record(record, domain, record_type):
    value = record if isinstance(record, str) else record.to_text().strip()
    allow_non_public_ip = bool_value_of_env("ALLOW_NON_PUBLIC_IP")

    try:
        ip = ipaddress.ip_address(value)
        # noqa See https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
        if ip.is_private or ip.is_reserved or ip.is_loopback:
            if allow_non_public_ip:
                logger.warning(
                    f"[!] DNS record type {record_type} for domain name "
                    f"{domain} resolves to a non public IP address {value}, "
                    "but allowed by config!"
                )
                return True
            else:
                logger.error(
                    f"[!] DNS record type {record_type} for domain name "
                    f"{domain} resolves to a non public IP address {value}. "
                )

                return False
    except ValueError:
        logger.info("[!] '%s' is not valid IP address!" % value)
        return False

    return True
