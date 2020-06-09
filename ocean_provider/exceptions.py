

class InvalidSignatureError(Exception):
    """ User signature is not valid."""


class ServiceAgreementExpired(Exception):
    """ Indicates the service agreement has already expired."""


class ServiceAgreementUnauthorized(Exception):
    """ Triggered when consumer is unauthorized to access the service."""
