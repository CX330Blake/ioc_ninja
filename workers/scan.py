"""
workers.scan
Lightweight re-export shim for the IoC background scan worker.

This module re-exports IoCScanWorker from the original `ioc_ui.py` so we can
gradually split responsibilities without changing runtime imports.
"""
from ioc_ninja.ui.ioc_ui import IoCScanWorker  # noqa: F401

__all__ = ["IoCScanWorker"]
