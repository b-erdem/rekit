"""Bot protection detectors."""

from rekit.botwall.detectors.cloudflare import CloudflareDetector
from rekit.botwall.detectors.datadome import DataDomeDetector
from rekit.botwall.detectors.akamai import AkamaiDetector
from rekit.botwall.detectors.perimeterx import PerimeterXDetector
from rekit.botwall.detectors.incapsula import IncapsulaDetector
from rekit.botwall.detectors.generic import GenericDetector

ALL_DETECTORS = [
    CloudflareDetector(),
    DataDomeDetector(),
    AkamaiDetector(),
    PerimeterXDetector(),
    IncapsulaDetector(),
    GenericDetector(),
]

__all__ = [
    "ALL_DETECTORS",
    "CloudflareDetector",
    "DataDomeDetector",
    "AkamaiDetector",
    "PerimeterXDetector",
    "IncapsulaDetector",
    "GenericDetector",
]
