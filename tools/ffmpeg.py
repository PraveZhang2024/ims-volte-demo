"""FFmpeg command helpers."""

from __future__ import annotations

from pathlib import Path


def wav_to_amrwb_command(wav_path: str | Path, amr_path: str | Path) -> list[str]:
    return [
        "ffmpeg",
        "-y",
        "-i",
        str(wav_path),
        "-ar",
        "16000",
        "-ac",
        "1",
        "-c:a",
        "libvo_amrwbenc",
        str(amr_path),
    ]


def amrwb_to_wav_command(amr_path: str | Path, wav_path: str | Path) -> list[str]:
    return ["ffmpeg", "-y", "-i", str(amr_path), str(wav_path)]
