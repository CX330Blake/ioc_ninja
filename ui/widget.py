"""
ui.widget
Lightweight re-export shim for IoC UI components.

This module intentionally imports and re-exports the core UI classes from the
original `ioc_ui.py` file to provide a clearer package structure without
duplicating or moving large amounts of logic in one step.

Keep implementation minimal so existing code paths continue to work while
we iterate on full modularization.
"""

# Import from top-level module so relative imports in the hosting environment
# (Binary Ninja plugin path) continue to resolve.
from ioc_ui import IoCNinjaWidget, IoCCheckboxProxyStyle  # noqa: F401

__all__ = ["IoCNinjaWidget", "IoCCheckboxProxyStyle"]
