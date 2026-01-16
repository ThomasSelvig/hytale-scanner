import asyncio
import ssl
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
        self.error_reason = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake_complete.set()
        elif isinstance(event, ConnectionTerminated):
            self.error_reason = (
                f"error_code={event.error_code}, reason={event.reason_phrase}"
            )
            self.connection_lost_event.set()


async def ping_hytale_server(
    host: str, port: int = 5520, timeout: float = 5.0
) -> PingResult:
    """
    Ping a Hytale QUIC server and measure handshake latency.
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["hytale/1"],  # Correct ALPN from Wireshark
        server_name="hynetic.net",  # SNI from Wireshark
    )

    # Disable certificate verification for game servers
    configuration.verify_mode = ssl.CERT_NONE

    start_time = time.perf_counter()

    try:
        loop = asyncio.get_event_loop()

        # Create the QUIC connection
        quic = QuicConnection(configuration=configuration)

        # Create UDP transport
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: HytalePinger(quic),
            remote_addr=(host, port),
        )

        # Initiate connection
        protocol._quic.connect(addr=(host, port), now=loop.time())
        protocol.transmit()

        try:
            handshake_task = asyncio.create_task(protocol.handshake_complete.wait())
            lost_task = asyncio.create_task(protocol.connection_lost_event.wait())

            done, pending = await asyncio.wait(
                [handshake_task, lost_task],
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            if protocol.handshake_complete.is_set():
                return PingResult(success=True, latency_ms=latency_ms)
            elif protocol.connection_lost_event.is_set():
                return PingResult(success=False, error=protocol.error_reason)
            else:
                return PingResult(success=False, error="Timeout")

        finally:
            transport.close()

    except Exception as e:
        return PingResult(success=False, error=f"{type(e).__name__}: {str(e)}")


async def ping_multiple(host: str, port: int = 5520, count: int = 5):
    """Run multiple pings and show statistics."""
    print(f"Pinging Hytale server at {host}:{port}")
    print("-" * 50)

    latencies = []
    for i in range(count):
        result = await ping_hytale_server(host, port)
        if result.success:
            latencies.append(result.latency_ms)
            print(f"  Reply from {host}: time={result.latency_ms:.2f}ms")
        else:
            print(f"  Request failed: {result.error}")

        if i < count - 1:
            await asyncio.sleep(0.5)

    print("-" * 50)
    if latencies:
        print(f"Ping statistics for {host}:")
        print(
            f"  Packets: Sent={count}, Received={len(latencies)}, Lost={count - len(latencies)}"
        )
        print(
            f"  Latency: Min={min(latencies):.2f}ms, Max={max(latencies):.2f}ms, Avg={sum(latencies)/len(latencies):.2f}ms"
        )
        return True
    else:
        print("All packets lost.")
        return False


async def main():
    import sys

    # Default to the server from your capture, or use command line arg
    host = sys.argv[1] if len(sys.argv) > 1 else "88.99.66.141"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5520

    await ping_multiple(host, port)


if __name__ == "__main__":
    asyncio.run(main())
