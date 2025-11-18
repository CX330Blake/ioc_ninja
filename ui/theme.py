"""
ui.theme
Re-export shim for theme / style related components.

Keep this module minimal: export the checkbox proxy style so callers
can import from `ioc_ninja.ui.theme` while we incrementally refactor other
theme helpers out of the large `ioc_ui.py`.
"""
from .ioc_ui import IoCCheckboxProxyStyle  # noqa: F401

__all__ = ["IoCCheckboxProxyStyle"]
