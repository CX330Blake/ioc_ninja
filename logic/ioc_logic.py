"""
Compatibility shim for the legacy `ioc_ninja.logic.ioc_logic` location.

This file re-exports the real implementation from `ioc_ninja.core.ioc_logic`.
Keeping this shim ensures existing imports that reference
`ioc_ninja.logic.ioc_logic` continue to work while the codebase is
refactored to use `ioc_ninja.core.ioc_logic`.
"""
from ioc_ninja.core.ioc_logic import *  # noqa: F401,F403

# Re-export a conservative __all__ if provided by the core implementation.
try:
    from ioc_ninja.core.ioc_logic import __all__ as __core_all__  # type: ignore
    __all__ = list(__core_all__)  # make a shallow copy
except Exception:
    # Fallback: export commonly used names
    __all__ = [
        "IOC_PATTERNS",
        "collect_strings_from_bv",
        "match_iocs_in_string",
        "extract_iocs_from_bv",
        "shannon_entropy",
        "is_printable",
    ]
