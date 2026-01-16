import asyncio
import fcntl
import ipaddress
import os
from typing import Set

from config import PROGRESS_FILE, RESULTS_FILE


class BlockClaimCoordinator:
    """Coordinates block claims across workers using file-based locking."""

    def __init__(self, progress_file: str = PROGRESS_FILE, results_file: str = RESULTS_FILE) -> None:
        """
        Initialize coordinator.

        Args:
            progress_file: Path to progress tracking file
            results_file: Path to results file
        """
        self.progress_file = progress_file
        self.results_file = results_file
        self.consumed_blocks: Set[str] = set()
        self.file_lock = asyncio.Lock()
        self.results_lock = asyncio.Lock()

    async def load_progress(self) -> None:
        """Load consumed blocks from progress file on startup."""
        if not os.path.exists(self.progress_file):
            # Create empty progress file
            with open(self.progress_file, 'w') as f:
                pass
            return

        async with self.file_lock:
            with open(self.progress_file, 'r') as f:
                for line in f:
                    block_str = line.strip()
                    if block_str:
                        self.consumed_blocks.add(block_str)

    async def claim_block(self, block: ipaddress.IPv4Network) -> bool:
        """
        Atomically claim a block by writing to progress file.

        Args:
            block: IPv4Network to claim

        Returns:
            True if block was successfully claimed, False if already consumed
        """
        block_str = str(block)

        async with self.file_lock:
            # Open in read-write mode, create if doesn't exist
            with open(self.progress_file, 'a+') as f:
                # Acquire exclusive file lock (cross-process coordination)
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)

                try:
                    # Seek to start to read existing content
                    f.seek(0)
                    consumed = set(line.strip() for line in f if line.strip())

                    # Check if already claimed
                    if block_str in consumed:
                        return False

                    # Write new block (at end due to append mode)
                    f.write(f'{block_str}\n')
                    f.flush()
                    os.fsync(f.fileno())

                    # Update in-memory cache
                    self.consumed_blocks.add(block_str)
                    return True

                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    async def record_found_server(self, ip: str, phase: str) -> None:
        """
        Append discovered server to results file.

        Args:
            ip: IP address of discovered server
            phase: Discovery phase description
        """
        async with self.results_lock:
            with open(self.results_file, 'a') as f:
                f.write(f'{ip}\n')
                f.flush()
                os.fsync(f.fileno())
