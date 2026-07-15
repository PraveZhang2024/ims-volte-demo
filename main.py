"""Command-line entry point for the IMS VoLTE demo client."""

from __future__ import annotations

import argparse
import logging
import sys

from app.config import load_config
from app.errors import ImsClientError
from app.orchestrator import ImsVolteOrchestrator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python IMS VoLTE demo client")
    parser.add_argument("--config", default="config/demo.yaml", help="Path to demo YAML config")
    parser.add_argument(
        "--mode",
        choices=("summary", "network-check", "register", "call"),
        default="summary",
        help="Validation stage to run",
    )
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    return parser.parse_args()


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)

    try:
        config = load_config(args.config)
        orchestrator = ImsVolteOrchestrator(config)

        if args.mode == "summary":
            orchestrator.print_summary()
        elif args.mode == "network-check":
            orchestrator.network_check()
        elif args.mode == "register":
            orchestrator.register()
        elif args.mode == "call":
            orchestrator.run_call()
        else:
            raise ImsClientError(f"Unsupported mode: {args.mode}")
    except ImsClientError as exc:
        logging.getLogger(__name__).error("%s", exc)
        return 1
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("Interrupted")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
