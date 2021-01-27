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


def is_safe_domain(domain):
    DNS_RESOLVER = dns.resolver.Resolver()
    try:
        ip_v4_records = DNS_RESOLVER.resolve(domain, "A", search=True)
    except Exception as e:
        ip_v4_records = None
        logger.info(
            "[i] Cannot get A record for domain '%s': %s\n" % (domain, e))
    try:
        ip_v6_records = DNS_RESOLVER.resolve(domain, "AAAA", search=True)
    except Exception as e:
        ip_v6_records = None
        logger.info(
            "[i] Cannot get AAAA record for domain '%s': %s\n" % (domain, e))

    if verify_dns_records(domain, ip_v4_records, "A") or verify_dns_records(domain, ip_v6_records, "AAAA"):
        return False
    return True


def verify_dns_records(domain, records, type):
    """
    Verify if one of the DNS records resolve to a non public IP address.
    Return a boolean indicating if any error has been detected.
    """
    if records is None:
        return False
    allow_non_public_ip = get_config().allow_non_public_ip
    error_detected = True
    for record in records:
        value = record.to_text().strip()
        try:
            ip = ipaddress.ip_address(value)
            # See https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
            if allow_non_public_ip and (ip.is_private or ip.is_reserved or ip.is_loopback):
                logger.warning("[!] DNS record type '%s' for domain name '%s' resolve to a non public IP address '%s', but allowed by config!" % (
                    type, domain, value))
                error_detected = False
            if ip.is_global:
                error_detected = False
            if error_detected == True:
                logger.error("[!] DNS record type '%s' for domain name '%s' resolve to a non public IP address '%s'!" % (
                    type, domain, value))

        except ValueError:
            error_detected = True
            logger.info("[!] '%s' is not valid IP address!" % value)
    return error_detected
