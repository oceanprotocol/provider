import logging
import ipaddress
import dns.resolver
from ocean_provider.utils.basics import get_config

from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def is_safe_url(url):
    if not is_safe_schema(url):
        return False

    result = urlparse(url)

    return is_safe_domain(result.netloc)


def is_safe_schema(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        return False


def is_ip(address):
    return address.replace('.', '').isnumeric()


def _get_records(domain, record_type):
    DNS_RESOLVER = dns.resolver.Resolver()
    try:
        return DNS_RESOLVER.resolve(domain, record_type, search=True)
    except Exception as e:
        logger.info(
            f"[i] Cannot get {record_type} record for domain {domain}: {e}\n"
        )

        return None


def is_safe_domain(domain):
    ip_v4_records = _get_records(domain, "A")
    ip_v6_records = _get_records(domain, "AAAA")

    result = (
        validate_dns_records(domain, ip_v4_records, "A") and
        validate_dns_records(domain, ip_v6_records, "AAAA")
    )

    if not is_ip(domain):
        return result

    return result and validate_dns_records(domain, domain, "")


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
    allow_non_public_ip = get_config().allow_non_public_ip

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
            else:
                logger.error(
                    f"[!] DNS record type {record_type} for domain name "
                    f"{domain} resolves to a non public IP address {value}, "
                    "but allowed by config!"
                )

                return False
    except ValueError:
        logger.info("[!] '%s' is not valid IP address!" % value)
        return False

    return True
