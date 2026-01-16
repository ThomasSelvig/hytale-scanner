# Hytale Scanner

A distributed, block-based scanner for discovering Hytale game servers across the internet.

Hytale servers use QUIC over UDP port 5520 with ALPN "hytale/1". This scanner attempts QUIC handshakes to identify active servers.

## Features

- **Block-based scanning**: Scans random /24 CIDR ranges (256 IPs per block)
- **Multi-worker**: Concurrent workers for parallel scanning
- **Progress tracking**: Resumes from where you left off via `progress.txt`
- **Results logging**: Discovered servers written to `found.txt`
- **Graceful shutdown**: Ctrl+C finishes current blocks, second Ctrl+C forces exit
- **IP filtering**: Automatically skips private/reserved address space

## Usage

### Block Scanner (Search for Servers)

```bash
# Run with default settings (4 workers, 100 concurrent scans)
uv run python scanner.py

# Customize workers and concurrency
uv run python scanner.py --workers 8 --concurrency 200

# Change block size or port
uv run python scanner.py --block-size 20 --port 5520
```

**CLI Arguments:**

- `--workers N`: Number of concurrent workers (default: 4)
- `--concurrency N`: Concurrent scans per worker (default: 100)
- `--block-size N`: CIDR block size in bits (default: 24 = /24 = 256 IPs)
- `--port N`: Target UDP port (default: 5520)

### Single IP Scanner (Test Individual Server)

```bash
# Scan a specific IP
uv run python main.py 88.99.66.141

# Scan with custom port
uv run python main.py 192.0.2.1 5520
```

## Files

- `progress.txt`: Consumed CIDR blocks (auto-created, persistent across runs)
- `found.txt`: Discovered server IPs (auto-created, one IP per line)

## Architecture

- **scanner.py**: Main orchestrator with CLI and signal handling
- **worker.py**: Worker that scans blocks with bounded concurrency
- **coordinator.py**: File-based coordination with atomic block claims
- **block_generator.py**: Random IP block generation with filtering
- **scanner_core.py**: QUIC scanning logic
- **main.py**: Single-IP scanner (reused by block scanner)
- **config.py**: Configuration constants

## TODO

- [ ] figure out how to determine if a server has whitelist or a password
  - 216.163.18.40, 212.132.73.225, 217.154.17.71 has password
  - 129.151.214.169, 185.185.43.27 don't respond? peer closes
  - 164.68.121.75 has a whitelist
