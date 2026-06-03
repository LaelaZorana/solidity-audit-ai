"""Detector package. Importing it registers all built-in detectors."""
from auditor.detectors import builtin  # noqa: F401  (import triggers registration)
from auditor.detectors.base import Detector, all_detectors, detector_catalog, register

__all__ = ["Detector", "register", "all_detectors", "detector_catalog"]
