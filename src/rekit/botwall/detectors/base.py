"""Base interfaces and data structures for bot protection detection."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class Difficulty(enum.Enum):
    """How hard it is to bypass a bot protection system."""

    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    IMPRACTICAL = "impractical"

    @property
    def description(self) -> str:
        return _DIFFICULTY_DESCRIPTIONS[self]

    @property
    def color(self) -> str:
        """Rich color name for terminal rendering."""
        return _DIFFICULTY_COLORS[self]


_DIFFICULTY_DESCRIPTIONS: Dict[Difficulty, str] = {
    Difficulty.TRIVIAL: "No active bot protection; standard requests work fine.",
    Difficulty.EASY: "Basic checks only; rotating headers/IPs is usually enough.",
    Difficulty.MEDIUM: "Requires proper TLS fingerprint and cookie handling.",
    Difficulty.HARD: "Requires JS execution, browser fingerprinting, or challenge solving.",
    Difficulty.IMPRACTICAL: "Full browser automation or managed challenge solving needed.",
}

_DIFFICULTY_COLORS: Dict[Difficulty, str] = {
    Difficulty.TRIVIAL: "green",
    Difficulty.EASY: "yellow",
    Difficulty.MEDIUM: "dark_orange",
    Difficulty.HARD: "red",
    Difficulty.IMPRACTICAL: "dark_red",
}


@dataclass
class ResponseData:
    """Normalized HTTP response data passed to every detector."""

    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    cookies: Dict[str, str]
    redirect_chain: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0


@dataclass
class Detection:
    """A single detection result from one detector."""

    system_name: str
    confidence: float  # 0.0 – 1.0
    difficulty: Difficulty
    evidence: List[str] = field(default_factory=list)
    bypass_hints: List[str] = field(default_factory=list)
    system_version: Optional[str] = None
    details: Dict[str, object] = field(default_factory=dict)


class Detector(ABC):
    """Abstract base for all bot-protection detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the protection system this detector covers."""

    @abstractmethod
    def detect(self, response_data: ResponseData) -> Optional[Detection]:
        """Inspect *response_data* and return a Detection if the system is found, else None."""
