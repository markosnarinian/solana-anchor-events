# pumpfun_anchor

A small, dependency-light Python extension (Rust + PyO3) that decodes
**Anchor 0.30+** program events out of Solana transaction log lines into plain
Python objects. No `anchorpy` dependency and no code generation — the decoder
parses an Anchor IDL (spec `0.1.0`) at runtime with the official
`anchor-lang-idl` crate and walks the `IdlType` tree to Borsh-decode event bytes
directly into dicts.

It is generic for any Anchor 0.30 IDL; pump.fun is just the tested target.

## Usage

```python
from pumpfun_anchor import EventDecoder

dec = EventDecoder(open("pumpfun.json").read())   # raw IDL JSON
events = dec.parse_logs(tx_log_lines)              # -> list[tuple[str, dict]]
print(dec.event_names)                             # e.g. ["TradeEvent", ...]
```

`parse_logs` accepts the program log lines (each like `"Program data: <base64>"`
or `"Program log: <base64>"`), skips anything that is not a recognizable event,
and never raises over a batch.

## Build

```bash
maturin develop          # build + install into the active venv
maturin build --release  # produce a wheel under target/wheels/
```

The wheel is `abi3-py39`, so a single artifact works on any CPython >= 3.9.
