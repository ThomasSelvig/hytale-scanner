import asyncio
import ipaddress
from typing import Optional

from block_generator import IPBlockGenerator
from coordinator import BlockClaimCoordinator
from scanner_core import scan_ip_two_phase
from config import MAX_CLAIM_ATTEMPTS


class Worker:
    """Scans IP blocks with bounded concurrency."""

    def __init__(
        self,
        worker_id: int,
        coordinator: BlockClaimCoordinator,
        generator: IPBlockGenerator,
        shutdown_event: asyncio.Event,
        force_shutdown_event: asyncio.Event,
        port: int,
        concurrency: int,
    ):
        """
        Initialize worker.

        Args:
            worker_id: Unique worker identifier
            coordinator: Block claim coordinator
            generator: IP block generator
            shutdown_event: Graceful shutdown event
            force_shutdown_event: Force shutdown event
            port: Target UDP port
            concurrency: Number of concurrent scans per block
        """
        self.worker_id = worker_id
        self.coordinator = coordinator
        self.generator = generator
        self.shutdown_event = shutdown_event
        self.force_shutdown_event = force_shutdown_event
        self.port = port
        self.concurrency = concurrency
        self.current_block: Optional[ipaddress.IPv4Network] = None

    async def run(self) -> None:
        """Main worker loop: claim blocks and scan them."""
        while not self.shutdown_event.is_set():
            # Try to claim a block
            block = await self._claim_unclaimed_block()
            if block is None:
                break  # No more unclaimed blocks or shutdown requested

            self.current_block = block
            print(f"[Worker {self.worker_id}] Scanning block {block}")

            try:
                await self.scan_block(block)
                print(f"[Worker {self.worker_id}] Completed block {block}")
            except asyncio.CancelledError:
                if self.force_shutdown_event.is_set():
                    print(f"[Worker {self.worker_id}] Force shutdown - block {block} marked consumed")
                    break
                raise
            finally:
                self.current_block = None

        print(f"[Worker {self.worker_id}] Exiting")

    async def _claim_unclaimed_block(self) -> Optional[ipaddress.IPv4Network]:
        """
        Try to claim an unclaimed block.

        Returns:
            IPv4Network if successfully claimed, None otherwise
        """
        if self.shutdown_event.is_set():
            return None  # No new claims during shutdown

        # Try up to MAX_CLAIM_ATTEMPTS to find and claim an unclaimed block
        for _ in range(MAX_CLAIM_ATTEMPTS):
            candidate = self.generator.generate_random_block()
            if await self.coordinator.claim_block(candidate):
                return candidate

        # Max attempts exceeded - likely near 100% coverage
        print(f"[Worker {self.worker_id}] Could not find unclaimed block after {MAX_CLAIM_ATTEMPTS} attempts")
        return None

    async def scan_block(self, block: ipaddress.IPv4Network) -> None:
        """
        Scan all IPs in block with bounded concurrency.

        Args:
            block: IPv4Network to scan
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = []

        for ip_str in self.generator.block_to_ips(block):
            task = asyncio.create_task(
                self._scan_ip_with_semaphore(ip_str, semaphore)
            )
            tasks.append(task)

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            # Force shutdown - cancel all pending tasks
            for task in tasks:
                if not task.done():
                    task.cancel()

            # Wait for cancellations to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def _scan_ip_with_semaphore(self, ip: str, semaphore: asyncio.Semaphore) -> None:
        """
        Scan single IP with semaphore for concurrency control.

        Args:
            ip: IP address to scan
            semaphore: Semaphore for limiting concurrency
        """
        async with semaphore:
            await scan_ip_two_phase(ip, self.port, self.coordinator)
