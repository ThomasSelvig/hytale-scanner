import asyncio
import time
from dataclasses import dataclass
from typing import Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


@dataclass
class PingResult:
    success: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class HytalePinger(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake_complete = asyncio.Event()
        self.connection_lost_event = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake_complete.set()
        elif isinstance(event, ConnectionTerminated):
            self.connection_lost_event.set()


async def ping_quic_server(
    host: str, port: int = 5520, timeout: float = 5.0
) -> PingResult:
    """
    Ping a QUIC server and measure handshake latency.
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hytale"],  # May need adjustment based on actual ALPN
        verify_mode=False,  # Skip certificate verification for game servers
    )
    # Disable certificate verification for self-signed/game certs
    configuration.verify_mode = False

    start_time = time.perf_counter()

    try:
        loop = asyncio.get_event_loop()

        # Create UDP connection
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: HytalePinger(
                QuicConnection(
                    configuration=configuration,
                    # server_name=host,
                ),
            ),
            remote_addr=(host, port),
        )

        # Connect and wait for handshake
        protocol._quic.connect(addr=(host, port), now=loop.time())
        protocol.transmit()

        try:
            # Wait for handshake or connection event
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(protocol.handshake_complete.wait()),
                    asyncio.create_task(protocol.connection_lost_event.wait()),
                ],
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            if protocol.handshake_complete.is_set():
                return PingResult(success=True, latency_ms=latency_ms)
            else:
                return PingResult(success=False, error="Connection terminated")

        except asyncio.TimeoutError:
            return PingResult(success=False, error="Timeout")
        finally:
            transport.close()

    except Exception as e:
        return PingResult(success=False, error=str(e))


async def ping_server_simple(
    host: str, port: int = 5520, timeout: float = 3.0
) -> PingResult:
    """
    Simple ping - just check if server responds to Initial packet.
    Doesn't require full handshake completion.
    """
    import os
    import socket

    # Build a minimal QUIC Initial packet
    # This is a simplified version - real QUIC has more complexity

    start_time = time.perf_counter()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Generate random DCID and SCID
        dcid = os.urandom(8)
        scid = os.urandom(8)

        # Build QUIC Initial packet (simplified)
        # Long header format for Initial packet
        packet = bytearray()

        # First byte: Long header (1) + Fixed bit (1) + Type (00 for Initial) + Reserved (00) + PN Length (00)
        packet.append(0xC0)  # 11000000 - Long header, Initial type

        # Version (QUIC v1 = 0x00000001)
        packet.extend([0x00, 0x00, 0x00, 0x01])

        # DCID length + DCID
        packet.append(len(dcid))
        packet.extend(dcid)

        # SCID length + SCID
        packet.append(len(scid))
        packet.extend(scid)

        # Token length (0 for initial)
        packet.append(0x00)

        # Length (2 bytes, includes packet number + payload)
        # Using variable-length encoding
        payload_len = 1200  # Minimum QUIC packet size
        packet.extend([0x44, 0xB0])  # ~1200 bytes

        # Packet number (1 byte for simplicity)
        packet.append(0x00)

        # CRYPTO frame with dummy ClientHello (padded)
        # Frame type 0x06 = CRYPTO
        packet.append(0x06)
        packet.append(0x00)  # Offset = 0
        packet.extend([0x40, 0x00])  # Length placeholder

        # Pad to minimum size
        while len(packet) < 1200:
            packet.append(0x00)

        # Send packet
        sock.sendto(bytes(packet), (host, port))

        # Wait for response
        try:
            data, addr = sock.recvfrom(2048)
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Check if it's a valid QUIC response
            if len(data) > 0:
                return PingResult(success=True, latency_ms=latency_ms)

        except socket.timeout:
            return PingResult(success=False, error="Timeout - no response")

    except Exception as e:
        return PingResult(success=False, error=str(e))
    finally:
        sock.close()

    return PingResult(success=False, error="Unknown error")


async def main():
    # Example usage
    host = "88.99.66.141"  # From your Wireshark capture
    port = 5520

    print(f"Pinging Hytale server at {host}:{port}...")
    print("-" * 50)

    # Try simple ping first (faster, less overhead)
    print("Method 1: Simple UDP ping...")
    result = await ping_server_simple(host, port)
    if result.success:
        print(f"  ✓ Server responded in {result.latency_ms:.2f}ms")
    else:
        print(f"  ✗ Failed: {result.error}")

    # Try full QUIC handshake ping
    print("\nMethod 2: Full QUIC handshake ping...")
    result = await ping_quic_server(host, port)
    if result.success:
        print(f"  ✓ Handshake completed in {result.latency_ms:.2f}ms")
    else:
        print(f"  ✗ Failed: {result.error}")


if __name__ == "__main__":
    asyncio.run(main())
