import ipaddress
import logging


def setup_logging(level: int = logging.INFO) -> None:
    """
    Setup structured logging for the scanner.

    Args:
        level: Logging level (default: INFO)
    """
    # Configure root logger
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        level=level,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Silence noisy third-party libraries
    # The aioquic library uses logger name "quic" (not "aioquic")
    logging.getLogger('quic').setLevel(logging.ERROR)

    # Suppress asyncio socket warnings
    logging.getLogger('asyncio').setLevel(logging.ERROR)


# Default scanner settings
DEFAULT_PORT = 5520
DEFAULT_WORKERS = 4
DEFAULT_CONCURRENCY = 100
DEFAULT_BLOCK_SIZE_BITS = 24  # /24 = 256 IPs

# Timeout values
# UDP check timeout (no longer used - kept for reference)
UDP_CHECK_TIMEOUT = 0.5

# QUIC handshake timeout
# Tuned based on testing: 1s catches slow servers without excessive wait.
# Shorter timeouts miss legitimate servers, longer timeouts slow down scanning.
QUIC_HANDSHAKE_TIMEOUT = 1.0

# File paths
PROGRESS_FILE = "progress.txt"
RESULTS_FILE = "found.txt"

# Block claim settings
# Maximum attempts to find unclaimed block before giving up.
# At 99% coverage, expected attempts ≈ 100. At 99.9% coverage ≈ 1000.
# This threshold assumes near-complete scan before worker stops.
# If workers stop early, consider increasing this value or implementing
# deterministic block allocation at high coverage levels.
MAX_CLAIM_ATTEMPTS = 1000

# IP ranges to skip (private/reserved)
SKIP_RANGES = [
    ipaddress.IPv4Network('0.0.0.0/8'),       # Current network
    ipaddress.IPv4Network('10.0.0.0/8'),      # Private
    ipaddress.IPv4Network('127.0.0.0/8'),     # Loopback
    ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
    ipaddress.IPv4Network('172.16.0.0/12'),   # Private
    ipaddress.IPv4Network('192.168.0.0/16'),  # Private
    ipaddress.IPv4Network('224.0.0.0/4'),     # Multicast
    ipaddress.IPv4Network('240.0.0.0/4'),     # Reserved
    ipaddress.IPv4Network('255.255.255.255/32'),  # Broadcast
]
