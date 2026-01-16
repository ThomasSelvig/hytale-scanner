import ipaddress
import secrets
from typing import List

from config import SKIP_RANGES


class IPBlockGenerator:
    """Generates random CIDR blocks for scanning, filtering private/reserved ranges."""

    def __init__(self, block_size_bits: int = 24):
        """
        Initialize block generator.

        Args:
            block_size_bits: CIDR block size (24 = /24 = 256 IPs)
        """
        self.block_size_bits = block_size_bits
        self.skip_ranges = SKIP_RANGES
        self.mask = (1 << 32) - (1 << (32 - block_size_bits))

    def is_valid_block(self, block: ipaddress.IPv4Network) -> bool:
        """
        Check if block is valid for scanning (not private/reserved).

        Args:
            block: IPv4Network to check

        Returns:
            True if block is valid for scanning
        """
        for skip_range in self.skip_ranges:
            if block.subnet_of(skip_range) or block.overlaps(skip_range):
                return False
        return True

    def generate_random_block(self) -> ipaddress.IPv4Network:
        """
        Generate a random CIDR block.

        Returns:
            Random IPv4Network (e.g., /24 block)
        """
        while True:
            # Generate random 32-bit integer
            random_int = secrets.randbelow(2**32)

            # Mask to block boundary
            network_int = random_int & self.mask

            # Convert to IPv4Network
            try:
                ip_addr = ipaddress.IPv4Address(network_int)
                block = ipaddress.IPv4Network(f"{ip_addr}/{self.block_size_bits}", strict=True)

                # Check if valid
                if self.is_valid_block(block):
                    return block
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                # Invalid network, retry
                continue

    def block_to_ips(self, block: ipaddress.IPv4Network) -> List[str]:
        """
        Convert CIDR block to list of IP strings.

        Args:
            block: IPv4Network to convert

        Returns:
            List of IP address strings (all addresses in block)
        """
        # Return all addresses in the block (including network and broadcast)
        return [str(ip) for ip in block]
