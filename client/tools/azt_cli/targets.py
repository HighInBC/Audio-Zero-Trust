from __future__ import annotations

TARGET_TO_ENV = {
    "atom-echo": "atom-echo",
    "atom-echos3r": "atom-echos3r",
}


def env_for_target(target: str) -> str:
    t = (target or "").strip().lower()
    if t not in TARGET_TO_ENV:
        raise ValueError(f"unknown target: {target}")
    return TARGET_TO_ENV[t]
