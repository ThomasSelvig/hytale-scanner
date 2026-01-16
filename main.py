import asyncio
import ssl

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

# found in wireshark in initial "Client Hello" from client to server
# under QUIC IETF/CRYPTO/TLSv1.3/Handshake/Extension: application_layer_protocol_negotiation
ALPN = "hytale/1"


class QuicProbe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake_complete = asyncio.Event()
        self.connection_failed = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake_complete.set()
        elif isinstance(event, ConnectionTerminated):
            self.connection_failed.set()


async def scan_quic_server(ip: str, port: int = 5520, timeout: float = 1.0) -> bool:
    """
    Scan if a QUIC server is running at the given IP and port.
    Returns True if QUIC handshake succeeds, False otherwise.
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[ALPN],
        server_name=ip,  # Use IP as SNI
    )
    configuration.verify_mode = ssl.CERT_NONE

    try:
        loop = asyncio.get_event_loop()
        quic = QuicConnection(configuration=configuration)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: QuicProbe(quic),
            remote_addr=(ip, port),
        )

        protocol._quic.connect(addr=(ip, port), now=loop.time())
        protocol.transmit()

        try:
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(protocol.handshake_complete.wait()),
                    asyncio.create_task(protocol.connection_failed.wait()),
                ],
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            return protocol.handshake_complete.is_set()

        finally:
            transport.close()

    except Exception:
        return False


async def main():
    import sys

    # hynetic.net
    ip = sys.argv[1] if len(sys.argv) > 1 else "88.99.66.141"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5520

    print(f"Scanning {ip}:{port}...")
    result = await scan_quic_server(ip, port)
    print(f"Server found: {result}")


if __name__ == "__main__":
    asyncio.run(main())
