"""Serve create_sangfor_wire_app() for manual Layer 10 first-contact hits.

Not the product Demo. Do not point DISPOSITION_ADAPTER_KIND=mock or
SOURCE_MODE=mock_xdr at this process. Canonical Mock remains /mock-xdr/v1.

Usage (uvicorn lives in the backend extra; system python3 often lacks it):

    cd backend && uv run python ../scripts/run_sangfor_wire_mock.py [--host 127.0.0.1] [--port 18080]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

try:
    import uvicorn  # noqa: E402
except ImportError:  # pragma: no cover - host python3 without backend extras
    sys.stderr.write(
        "uvicorn is not installed. From the backend dir run:\n"
        "  cd backend && uv run python ../scripts/run_sangfor_wire_mock.py\n"
    )
    raise SystemExit(1) from None

from app.adapters.sangfor.wire_mock import create_sangfor_wire_app  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("run_sangfor_wire_mock")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Sangfor vendor wire mock (not Demo, not production XDR)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args(argv)
    app = create_sangfor_wire_app()
    logger.info(
        "starting Sangfor wire mock on http://%s:%s (OpenAPI /api/xdr/v1; not /mock-xdr/v1)",
        args.host,
        args.port,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
