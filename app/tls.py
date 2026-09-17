"""Make Python's TLS verification use the operating system trust store.

Python's ``requests`` verifies certificates against the bundled ``certifi`` CA
set. Some hosts (e.g. servers that rely on the client fetching a missing
intermediate via AIA, or environments with a corporate/internal root CA) verify
fine with ``curl`` — which uses the OS trust store — but fail under ``certifi``
with "unable to get local issuer certificate".

Injecting ``truststore`` routes verification through the OS trust store
(macOS Keychain, Windows cert store, or the system store on Linux), mirroring
``curl`` while still fully verifying certificates.
"""

from __future__ import annotations

from app.logging import get_logger

_injected = False


def enable_system_trust() -> bool:
    """Route TLS verification through the OS trust store (idempotent).

    Returns True if the system trust store is now in use, False if ``truststore``
    is unavailable (in which case the default ``certifi`` behavior remains).
    """
    global _injected
    if _injected:
        return True

    logger = get_logger()
    try:
        import truststore
    except ImportError:
        logger.debug("truststore not installed; using certifi CA bundle for TLS.")
        return False

    truststore.inject_into_ssl()
    _injected = True
    logger.debug("TLS verification is using the OS system trust store (truststore).")
    return True
