import asyncio

from coordinator import BlockClaimCoordinator
from main import scan_quic_server
from config import UDP_CHECK_TIMEOUT, QUIC_HANDSHAKE_TIMEOUT


class SimpleUDPProtocol(asyncio.DatagramProtocol):
    """Minimal UDP protocol for port checking."""

    def __init__(self):
        self.response_received = asyncio.Event()

    def datagram_received(self, data, addr):
        """Called when a datagram is received."""
        self.response_received.set()

    def error_received(self, exc):
        """Called when an error is received (e.g., ICMP port unreachable)."""
        pass


async def quick_udp_check(ip: str, port: int, timeout: float = UDP_CHECK_TIMEOUT) -> bool:
    """
    Fast UDP port check before expensive QUIC handshake.

    Args:
        ip: Target IP address
        port: Target UDP port
        timeout: Timeout in seconds

    Returns:
        True if port potentially open (endpoint created successfully)
        False if port filtered/unreachable
    """
    try:
        loop = asyncio.get_event_loop()

        # Create datagram endpoint with minimal protocol
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                SimpleUDPProtocol,
                remote_addr=(ip, port),
            ),
            timeout=timeout
        )

        try:
            # Send empty UDP packet
            transport.sendto(b'', (ip, port))

            # Wait briefly for any response (but don't require one)
            # UDP is connectionless, so we mainly care if endpoint creation succeeded
            await asyncio.sleep(0.1)

        finally:
            transport.close()

        return True

    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        # Timeout or connection error = port likely filtered/unreachable
        return False


async def scan_ip_two_phase(
    ip: str,
    port: int,
    coordinator: BlockClaimCoordinator,
) -> None:
    """
    Scan IP with QUIC handshake.

    Note: The original two-phase approach (UDP check then QUIC) was found to be
    ineffective since UDP endpoint creation always succeeds (UDP is connectionless).
    The QUIC handshake itself IS the effective port check.

    Args:
        ip: Target IP address
        port: Target UDP port
        coordinator: Block claim coordinator for recording results
    """
    # Attempt QUIC handshake (this sends UDP packets and waits for QUIC response)
    quic_success = await scan_quic_server(ip, port, timeout=QUIC_HANDSHAKE_TIMEOUT)

    if quic_success:
        print(f"[FOUND] {ip}:{port} - Hytale server discovered!")
        await coordinator.record_found_server(ip, "QUIC handshake succeeded")
