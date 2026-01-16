import asyncio

from quic_scanner import scan_quic_server


async def main() -> None:
    import sys

    # hynetic.net
    ip = sys.argv[1] if len(sys.argv) > 1 else "88.99.66.141"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5520

    print(f"Scanning {ip}:{port}...")
    result = await scan_quic_server(ip, port)
    print(f"Server found: {result}")


if __name__ == "__main__":
    asyncio.run(main())
