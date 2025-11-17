"""
styles.theme
Re-export shim for theme / style related components.

Keep this module minimal for now: export the checkbox proxy style so callers
can import from styles.theme while we incrementally refactor other theme helpers
out of the large `ioc_ui.py`.
"""
from ioc_ui import IoCCheckboxProxyStyle  # noqa: F401

__all__ = ["IoCCheckboxProxyStyle"]
