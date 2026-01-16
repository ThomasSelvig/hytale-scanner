import asyncio

from quic_scanner import scan_quic_server


async def main() -> None:
    import socket
    import sys

    # hynetic.net
    host = sys.argv[1] if len(sys.argv) > 1 else "88.99.66.141"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5520

    # Resolve hostname to IP if necessary
    try:
        ip = socket.gethostbyname(host)
        if host != ip:
            print(f"Resolved {host} to {ip}")
    except socket.gaierror as e:
        print(f"Failed to resolve hostname {host}: {e}")
        return

    print(f"Scanning {ip}:{port}...")
    result = await scan_quic_server(ip, port)
    print(f"Server found: {result}")


if __name__ == "__main__":
    asyncio.run(main())
