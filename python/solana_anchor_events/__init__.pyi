from collections.abc import Sequence
from typing import Any

__all__ = ["EventDecoder"]
__version__: str

class EventDecoder:
    """Decodes Anchor 0.30+ program events from Solana transaction log lines."""

    def __init__(self, idl_json: str) -> None:
        """Build a decoder from an Anchor IDL JSON string (spec ``0.1.0``).

        Raises:
            ValueError: if the IDL cannot be parsed or is unsupported.
        """
        ...

    def parse_logs(self, logs: Sequence[str]) -> list[tuple[str, dict[str, Any]]]:
        """Decode every recognizable event from a batch of program log lines.

        Lines that are not events, fail to base64-decode, match no known event
        discriminator, or fail to Borsh-decode are skipped. Never raises over a
        batch. Returns ``(event_name, fields)`` tuples in log order.
        """
        ...

    @property
    def event_names(self) -> list[str]:
        """Names of all events declared in the IDL, in declaration order."""
        ...
