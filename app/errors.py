"""Shared exception types."""


class ImsClientError(Exception):
    """Base exception for expected IMS client failures."""


class ConfigError(ImsClientError):
    """Raised when the YAML configuration is missing or invalid."""


class NetworkError(ImsClientError):
    """Raised when IMS APN networking checks fail."""


class SipError(ImsClientError):
    """Raised for SIP parsing, building, transport, or flow failures."""


class SipReceiveTimeout(SipError):
    """Raised when no complete SIP message arrives before the receive timeout."""


class AkaError(ImsClientError):
    """Raised for IMS AKA and digest failures."""


class IpsecError(ImsClientError):
    """Raised for Security Agreement or XFRM command failures."""


class MediaError(ImsClientError):
    """Raised for RTP or AMR-WB media failures."""
