import asyncio
import logging
import ssl

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

logger = logging.getLogger(__name__)

# Suppress verbose aioquic connection close logs
logging.getLogger("aioquic").setLevel(logging.WARNING)

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
        loop = asyncio.get_running_loop()
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
            # Graceful QUIC connection close
            protocol._quic.close()
            protocol.transmit()  # Send CONNECTION_CLOSE frame

            # Brief delay to allow event loop to flush socket buffers
            await asyncio.sleep(0.01)

            transport.close()

    except asyncio.TimeoutError:
        logger.debug("QUIC handshake timeout: %s:%d", ip, port)
        return False
    except OSError as e:
        logger.debug("Network error scanning %s:%d - %s", ip, port, e)
        return False
    except Exception as e:
        logger.error("Unexpected error scanning %s:%d - %s", ip, port, e, exc_info=True)
        return False
