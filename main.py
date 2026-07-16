"""Command-line entry point for the IMS VoLTE demo client."""

from __future__ import annotations

import argparse
import logging
import signal
import sys

from app.config import load_config
from app.errors import ImsClientError
from app.orchestrator import ImsVolteOrchestrator

DEFAULT_CALL_DURATION_SECONDS = 30.0


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
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=None,
        help="Call duration in seconds. Defaults to 30. Use <= 0 to loop media until BYE or signal.",
    )
    return parser.parse_args()


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def configure_signal_handlers() -> None:
    def _raise_keyboard_interrupt(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for signal_name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            signal.signal(signum, _raise_keyboard_interrupt)


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    configure_signal_handlers()

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
            duration_seconds = args.duration_seconds
            if duration_seconds is None:
                duration_seconds = DEFAULT_CALL_DURATION_SECONDS
                logging.getLogger(__name__).info(
                    "--duration-seconds not provided; using default %.0f seconds",
                    duration_seconds,
                )
            orchestrator.run_call(duration_seconds=duration_seconds)
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
