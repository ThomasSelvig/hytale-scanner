import argparse
import asyncio
import signal
from typing import List

from block_generator import IPBlockGenerator
from coordinator import BlockClaimCoordinator
from worker import Worker
from config import (
    DEFAULT_WORKERS,
    DEFAULT_CONCURRENCY,
    DEFAULT_BLOCK_SIZE_BITS,
    DEFAULT_PORT,
    PROGRESS_FILE,
    RESULTS_FILE,
)


class Scanner:
    """Main scanner orchestrator managing workers and shutdown."""

    def __init__(
        self,
        num_workers: int = DEFAULT_WORKERS,
        concurrency: int = DEFAULT_CONCURRENCY,
        block_size: int = DEFAULT_BLOCK_SIZE_BITS,
        port: int = DEFAULT_PORT,
    ):
        """
        Initialize scanner.

        Args:
            num_workers: Number of concurrent worker tasks
            concurrency: Scans per worker
            block_size: CIDR block size in bits (24 = /24)
            port: Target UDP port
        """
        self.num_workers = num_workers
        self.concurrency = concurrency
        self.block_size = block_size
        self.port = port
        self.shutdown_requested = asyncio.Event()
        self.force_shutdown = asyncio.Event()
        self.coordinator: BlockClaimCoordinator = None
        self.workers: List[Worker] = []
        self.worker_tasks: List[asyncio.Task] = []

    async def run(self) -> None:
        """Start scanner with all workers."""
        # Setup signal handlers using asyncio
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self._signal_handler_sync)

        # Initialize coordinator and load progress
        self.coordinator = BlockClaimCoordinator(PROGRESS_FILE, RESULTS_FILE)
        await self.coordinator.load_progress()
        print(f"Loaded {len(self.coordinator.consumed_blocks)} consumed blocks")

        # Create generator
        generator = IPBlockGenerator(block_size_bits=self.block_size)

        # Launch workers
        self.worker_tasks = []
        for i in range(self.num_workers):
            worker = Worker(
                worker_id=i,
                coordinator=self.coordinator,
                generator=generator,
                shutdown_event=self.shutdown_requested,
                force_shutdown_event=self.force_shutdown,
                port=self.port,
                concurrency=self.concurrency,
            )
            self.workers.append(worker)
            task = asyncio.create_task(worker.run())
            self.worker_tasks.append(task)

        print(f"Started {self.num_workers} workers with {self.concurrency} concurrent scans each")
        print(f"Scanning UDP port {self.port} for Hytale servers...")
        print(f"Press Ctrl+C to gracefully shutdown (finish current blocks)")
        print(f"Press Ctrl+C twice to force shutdown\n")

        # Wait for all workers to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        print("\nAll workers completed")
        print(f"Total blocks consumed: {len(self.coordinator.consumed_blocks)}")

    def _signal_handler_sync(self) -> None:
        """Handle SIGINT signals (called from signal handler context)."""
        if self.shutdown_requested.is_set():
            # Second SIGINT - force immediate shutdown
            print("\n[FORCE SHUTDOWN] Canceling in-flight scans...")
            self.force_shutdown.set()

            # Cancel all worker tasks
            for task in self.worker_tasks:
                if not task.done():
                    task.cancel()
        else:
            # First SIGINT - graceful shutdown
            print("\n[GRACEFUL SHUTDOWN] Finishing current blocks... (Ctrl+C again to force)")
            self.shutdown_requested.set()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hytale Server Scanner - Block-based IP scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent workers",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Number of concurrent scans per worker",
    )
    parser.add_argument(
        "--block-size",
        type=int,
        default=DEFAULT_BLOCK_SIZE_BITS,
        help="CIDR block size in bits (24 = /24 = 256 IPs)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Target UDP port",
    )
    return parser.parse_args()


async def main():
    """Main entry point."""
    args = parse_args()
    scanner = Scanner(
        num_workers=args.workers,
        concurrency=args.concurrency,
        block_size=args.block_size,
        port=args.port,
    )
    await scanner.run()


if __name__ == "__main__":
    asyncio.run(main())
