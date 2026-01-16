import asyncio
import logging

from coordinator import BlockClaimCoordinator
from quic_scanner import scan_quic_server
from config import QUIC_HANDSHAKE_TIMEOUT

logger = logging.getLogger(__name__)


async def scan_ip(
    ip: str,
    port: int,
    coordinator: BlockClaimCoordinator,
) -> None:
    """
    Scan IP with QUIC handshake to detect Hytale server.

    The QUIC handshake sends UDP packets with the Hytale ALPN and waits for
    a valid QUIC response. This is the authoritative check for server presence.

    Args:
        ip: Target IP address
        port: Target UDP port
        coordinator: Block claim coordinator for recording results
    """
    # Attempt QUIC handshake
    quic_success = await scan_quic_server(ip, port, timeout=QUIC_HANDSHAKE_TIMEOUT)

    if quic_success:
        logger.info("FOUND: %s:%d - Hytale server discovered!", ip, port)
        await coordinator.record_found_server(ip, "QUIC handshake succeeded")
