from __future__ import annotations

import random

from skidc.dispatcher.config import WorkerConfig


def choose_worker(candidates: list[WorkerConfig], running_counts: dict[str, int]) -> list[WorkerConfig]:
    """Order eligible workers: lowest priority number first, then fewest running
    tasks (load balancing), then random to break remaining ties fairly."""
    grouped = sorted(
        candidates,
        key=lambda worker: (
            worker.priority,
            running_counts.get(worker.name, 0),
            random.random(),
        ),
    )
    return grouped
