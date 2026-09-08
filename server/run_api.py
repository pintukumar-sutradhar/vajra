"""Run the VAJRA platform API server.

Usage:  python server/run_api.py  (defaults to http://0.0.0.0:8000)
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn  # noqa: E402


def main():
    host = os.environ.get("VAJRA_API_HOST", "0.0.0.0")
    port = int(os.environ.get("VAJRA_API_PORT", "8000"))
    uvicorn.run("server.app.main:app", host=host, port=port,
                reload=False, log_level="info")


if __name__ == "__main__":
    main()