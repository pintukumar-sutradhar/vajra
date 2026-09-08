"""Run the VAJRA platform scan worker.

Usage:  python server/run_worker.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.worker.queue import worker_main  # noqa: E402

if __name__ == "__main__":
    worker_main()