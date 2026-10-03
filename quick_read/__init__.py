"""quick-read: fast single-URL reader for LLM agents."""
__version__ = "0.1.0"

from .core import quick_read  # noqa: E402
from .injection import redact, risk, scan  # noqa: E402

__all__ = ["quick_read", "risk", "scan", "redact", "__version__"]
