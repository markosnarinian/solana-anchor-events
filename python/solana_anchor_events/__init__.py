"""Decode Anchor 0.30+ program events from Solana transaction logs.

The public API is implemented in the compiled Rust extension and re-exported
here so the package also carries type stubs (see ``__init__.pyi``).
"""

from ._solana_anchor_events import EventDecoder

__all__ = ["EventDecoder"]
__version__ = "0.1.0"
