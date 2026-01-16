import ipaddress

# Default scanner settings
DEFAULT_PORT = 5520
DEFAULT_WORKERS = 4
DEFAULT_CONCURRENCY = 100
DEFAULT_BLOCK_SIZE_BITS = 24  # /24 = 256 IPs

# Timeout values
UDP_CHECK_TIMEOUT = 0.5  # Fast UDP port check
QUIC_HANDSHAKE_TIMEOUT = 1.0  # Full QUIC handshake

# File paths
PROGRESS_FILE = "progress.txt"
RESULTS_FILE = "found.txt"

# Block claim settings
MAX_CLAIM_ATTEMPTS = 1000  # Max attempts to find unclaimed block

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
