"""External command wrapper with explicit dry-run support."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import subprocess

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    executed: bool


class CommandRunner:
    def __init__(self, *, execute: bool = True, timeout_seconds: float = 10.0) -> None:
        self.execute = execute
        self.timeout_seconds = timeout_seconds

    def run(self, args: list[str], *, check: bool = True) -> CommandResult:
        LOGGER.debug("Command: %s", " ".join(args))
        if not self.execute:
            LOGGER.info("Dry-run command: %s", " ".join(args))
            return CommandResult(args=args, returncode=0, stdout="", stderr="", executed=False)

        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        result = CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            executed=True,
        )
        if check and completed.returncode != 0:
            raise RuntimeError(
                f"Command failed ({completed.returncode}): {' '.join(args)}\n{completed.stderr}"
            )
        return result
