# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A distributed Hytale game server scanner that discovers servers across the internet by attempting QUIC handshakes over UDP port 5520 with ALPN `hytale/1`.

## Commands

```bash
# Install dependencies
uv sync

# Block scanner - search for servers across random IP ranges
uv run python scanner.py                              # default: 4 workers, 100 concurrency
uv run python scanner.py --workers 8 --concurrency 200  # custom settings

# Single IP scanner - test specific server
uv run python main.py <ip> [port]
uv run python main.py 88.99.66.141        # default port 5520
uv run python main.py 192.168.1.100 5520  # explicit port
```

## Architecture

### Core Scanning (`main.py`)
- `QuicProbe` - Protocol handler that tracks handshake completion via asyncio Events
- `scan_quic_server(ip, port, timeout) -> bool` - Main scanning function, returns True if QUIC handshake succeeds
- Uses `aioquic` library for QUIC protocol implementation
- Certificate verification is disabled (`ssl.CERT_NONE`) since game servers use self-signed certs
- Uses IP address as SNI (Server Name Indication)

### Block Scanner Components
- `scanner.py` - Main orchestrator with CLI and graceful shutdown (SIGINT handling)
- `worker.py` - Worker tasks that scan blocks with bounded concurrency (asyncio.Semaphore)
- `coordinator.py` - File-based coordination with fcntl locking for atomic block claims
- `block_generator.py` - Random /24 CIDR generation, filters private/reserved ranges
- `scanner_core.py` - Wraps `scan_quic_server()` with result logging
- `config.py` - Configuration constants (workers, concurrency, timeouts, IP filters)

### Data Flow
1. Workers claim random /24 blocks atomically via `progress.txt` (fcntl locks)
2. Each worker scans all 256 IPs in block with bounded concurrency (default: 100 concurrent)
3. Successful QUIC handshakes appended to `found.txt` immediately
4. Blocks marked consumed when claimed (not when completed) to prevent duplicate work

### Files Generated
- `progress.txt` - Consumed CIDR blocks (one per line, e.g., "1.2.3.0/24")
- `found.txt` - Discovered server IPs (one per line)

### Key Design Decisions
- Random block generation provides natural load balancing across workers
- File-based coordination supports multi-process/multi-machine deployment
- In-memory consumed blocks set for O(1) lookup
- Graceful shutdown: first Ctrl+C finishes current blocks, second Ctrl+C forces exit
