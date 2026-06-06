//! Generic Anchor 0.30+ event log decoder exposed to Python via PyO3.
//!
//! The IDL (spec `0.1.0`) is parsed at runtime with the official
//! `anchor_lang_idl` crate; the resulting `IdlType` tree is then walked to
//! Borsh-decode program event bytes straight into Python objects. No code
//! generation, no `declare_program!`, no `anchorpy`.

use std::collections::HashMap;

use anchor_lang_idl::convert::convert_idl;
use anchor_lang_idl::types::{
    Idl, IdlArrayLen, IdlDefinedFields, IdlEnumVariant, IdlType, IdlTypeDef, IdlTypeDefTy,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::IntoPyObjectExt;

/// Convert any `IntoPyObject` value into an owned `Bound<PyAny>`, mapping the
/// conversion error into a `String` so it can flow through the decoder's
/// `Result<_, String>` channel (and become a "skip this event" outcome).
fn to_any<'py, T>(py: Python<'py>, value: T) -> Result<Bound<'py, PyAny>, String>
where
    T: IntoPyObject<'py>,
{
    value.into_bound_py_any(py).map_err(|e| e.to_string())
}

/// A forward-only cursor over a Borsh-encoded byte buffer (little-endian).
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Borrow the next `n` bytes and advance, or error if the buffer is short.
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let data = self.data;
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "length overflow".to_string())?;
        if end > data.len() {
            return Err(format!(
                "unexpected end of buffer: need {n} byte(s) at offset {}, have {}",
                self.pos,
                data.len()
            ));
        }
        let slice = &data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Borrow the next `N` bytes as a fixed-size array.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let slice = self.take(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }
}

/// Read a Borsh `u32` length prefix as a `usize`.
fn read_u32_len(cur: &mut Cursor) -> Result<usize, String> {
    Ok(u32::from_le_bytes(cur.take_array::<4>()?) as usize)
}

/// Base58-encode 32 raw Pubkey bytes.
fn pubkey_to_bs58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Build a Python `int` from little-endian bytes (used for u256/i256).
/// Best-effort: routes through Python's `int.from_bytes`; never panics.
fn pyint_from_le_bytes<'py>(
    py: Python<'py>,
    bytes: &[u8],
    signed: bool,
) -> Result<Bound<'py, PyAny>, String> {
    let builtins = py.import("builtins").map_err(|e| e.to_string())?;
    let int_cls = builtins.getattr("int").map_err(|e| e.to_string())?;
    let py_bytes = PyBytes::new(py, bytes);
    let kwargs = PyDict::new(py);
    kwargs
        .set_item("signed", signed)
        .map_err(|e| e.to_string())?;
    int_cls
        .call_method("from_bytes", (py_bytes, "little"), Some(&kwargs))
        .map_err(|e| e.to_string())
}

/// Precomputed decode plan for a single event.
struct EventLayout {
    discriminator: Vec<u8>,
    name: String,
    fields: Option<IdlDefinedFields>,
}

/// Decodes Anchor 0.30+ program events from Solana transaction log lines.
#[pyclass]
struct EventDecoder {
    events: Vec<EventLayout>,
    types: HashMap<String, IdlTypeDef>,
}

#[pymethods]
impl EventDecoder {
    /// Parse an Anchor IDL JSON string and build the decoder.
    ///
    /// Raises `ValueError` on malformed or unsupported IDLs.
    #[new]
    fn new(idl_json: &str) -> PyResult<Self> {
        let idl: Idl = convert_idl(idl_json.as_bytes())
            .map_err(|e| PyValueError::new_err(format!("failed to parse IDL: {e}")))?;

        let types: HashMap<String, IdlTypeDef> = idl
            .types
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();

        let mut events = Vec::with_capacity(idl.events.len());
        for ev in &idl.events {
            // An IdlEvent only carries name + discriminator; its field layout
            // is the same-named struct in idl.types.
            let type_def = types.get(&ev.name).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "event '{}' has no matching type definition in idl.types",
                    ev.name
                ))
            })?;
            let fields = match &type_def.ty {
                IdlTypeDefTy::Struct { fields } => fields.clone(),
                _ => {
                    return Err(PyValueError::new_err(format!(
                        "event '{}' type definition is not a struct",
                        ev.name
                    )))
                }
            };
            events.push(EventLayout {
                discriminator: ev.discriminator.clone(),
                name: ev.name.clone(),
                fields,
            });
        }

        Ok(EventDecoder { events, types })
    }

    /// Decode every recognizable event from a batch of program log lines.
    ///
    /// Lines that are not events, fail to base64-decode, match no known
    /// discriminator, or fail to Borsh-decode are silently skipped. Never
    /// raises over a batch.
    fn parse_logs<'py>(&self, py: Python<'py>, logs: Vec<String>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for line in logs {
            let payload = match line
                .strip_prefix("Program data: ")
                .or_else(|| line.strip_prefix("Program log: "))
            {
                Some(rest) => rest.trim(),
                None => continue,
            };
            let decoded = match BASE64.decode(payload) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if decoded.len() < 8 {
                continue;
            }
            let (disc, body) = decoded.split_at(8);
            let layout = match self
                .events
                .iter()
                .find(|e| e.discriminator.as_slice() == disc)
            {
                Some(l) => l,
                None => continue,
            };
            let mut cur = Cursor::new(body);
            let data = match self.decode_fields(py, &mut cur, &layout.fields) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let item = match (layout.name.as_str(), data).into_bound_py_any(py) {
                Ok(t) => t,
                Err(_) => continue,
            };
            out.append(item)?;
        }
        Ok(out)
    }

    /// Names of all events declared in the IDL, in declaration order.
    #[getter]
    fn event_names(&self) -> Vec<String> {
        self.events.iter().map(|e| e.name.clone()).collect()
    }
}

impl EventDecoder {
    /// Decode a set of (possibly absent) Borsh fields: named -> dict,
    /// tuple -> list, none -> empty dict.
    fn decode_fields<'py>(
        &self,
        py: Python<'py>,
        cur: &mut Cursor,
        fields: &Option<IdlDefinedFields>,
    ) -> Result<Bound<'py, PyAny>, String> {
        match fields {
            None => Ok(PyDict::new(py).into_any()),
            Some(IdlDefinedFields::Named(named)) => {
                let dict = PyDict::new(py);
                for field in named {
                    let value = self.decode_type(py, cur, &field.ty)?;
                    dict.set_item(&field.name, value)
                        .map_err(|e| e.to_string())?;
                }
                Ok(dict.into_any())
            }
            Some(IdlDefinedFields::Tuple(types)) => {
                let list = PyList::empty(py);
                for ty in types {
                    let value = self.decode_type(py, cur, ty)?;
                    list.append(value).map_err(|e| e.to_string())?;
                }
                Ok(list.into_any())
            }
        }
    }

    /// Decode a Borsh enum: a 1-byte tag selects the variant. Unit variants
    /// decode to their name (str); data variants to `{name: <fields>}`.
    fn decode_enum<'py>(
        &self,
        py: Python<'py>,
        cur: &mut Cursor,
        variants: &[IdlEnumVariant],
    ) -> Result<Bound<'py, PyAny>, String> {
        let tag = cur.take(1)?[0] as usize;
        let variant = variants
            .get(tag)
            .ok_or_else(|| format!("enum discriminant {tag} out of range"))?;
        match &variant.fields {
            None => to_any(py, variant.name.as_str()),
            Some(_) => {
                let inner = self.decode_fields(py, cur, &variant.fields)?;
                let dict = PyDict::new(py);
                dict.set_item(&variant.name, inner)
                    .map_err(|e| e.to_string())?;
                Ok(dict.into_any())
            }
        }
    }

    /// Resolve and decode a user-defined type by name.
    fn decode_defined<'py>(
        &self,
        py: Python<'py>,
        cur: &mut Cursor,
        name: &str,
    ) -> Result<Bound<'py, PyAny>, String> {
        let type_def = self
            .types
            .get(name)
            .ok_or_else(|| format!("unknown defined type '{name}'"))?;
        match &type_def.ty {
            IdlTypeDefTy::Struct { fields } => self.decode_fields(py, cur, fields),
            IdlTypeDefTy::Enum { variants } => self.decode_enum(py, cur, variants),
            IdlTypeDefTy::Type { alias } => self.decode_type(py, cur, alias),
        }
    }

    /// Borsh-decode a single value of the given IDL type.
    #[allow(unreachable_patterns)]
    fn decode_type<'py>(
        &self,
        py: Python<'py>,
        cur: &mut Cursor,
        ty: &IdlType,
    ) -> Result<Bound<'py, PyAny>, String> {
        match ty {
            IdlType::Bool => to_any(py, cur.take(1)?[0] != 0),
            IdlType::U8 => to_any(py, cur.take(1)?[0]),
            IdlType::I8 => to_any(py, cur.take(1)?[0] as i8),
            IdlType::U16 => to_any(py, u16::from_le_bytes(cur.take_array()?)),
            IdlType::I16 => to_any(py, i16::from_le_bytes(cur.take_array()?)),
            IdlType::U32 => to_any(py, u32::from_le_bytes(cur.take_array()?)),
            IdlType::I32 => to_any(py, i32::from_le_bytes(cur.take_array()?)),
            IdlType::F32 => to_any(py, f32::from_le_bytes(cur.take_array()?)),
            IdlType::U64 => to_any(py, u64::from_le_bytes(cur.take_array()?)),
            IdlType::I64 => to_any(py, i64::from_le_bytes(cur.take_array()?)),
            IdlType::F64 => to_any(py, f64::from_le_bytes(cur.take_array()?)),
            IdlType::U128 => to_any(py, u128::from_le_bytes(cur.take_array()?)),
            IdlType::I128 => to_any(py, i128::from_le_bytes(cur.take_array()?)),
            IdlType::U256 => pyint_from_le_bytes(py, &cur.take_array::<32>()?, false),
            IdlType::I256 => pyint_from_le_bytes(py, &cur.take_array::<32>()?, true),
            IdlType::Bytes => {
                let len = read_u32_len(cur)?;
                let raw = cur.take(len)?;
                Ok(PyBytes::new(py, raw).into_any())
            }
            IdlType::String => {
                let len = read_u32_len(cur)?;
                let raw = cur.take(len)?;
                let s = std::str::from_utf8(raw).map_err(|e| format!("invalid utf-8: {e}"))?;
                to_any(py, s)
            }
            IdlType::Pubkey => to_any(py, pubkey_to_bs58(&cur.take_array::<32>()?)),
            IdlType::Option(inner) => {
                if cur.take(1)?[0] == 0 {
                    Ok(py.None().into_bound(py))
                } else {
                    self.decode_type(py, cur, inner)
                }
            }
            IdlType::Vec(inner) => {
                let len = read_u32_len(cur)?;
                let list = PyList::empty(py);
                for _ in 0..len {
                    let value = self.decode_type(py, cur, inner)?;
                    list.append(value).map_err(|e| e.to_string())?;
                }
                Ok(list.into_any())
            }
            IdlType::Array(inner, len) => {
                let n = match len {
                    IdlArrayLen::Value(n) => *n,
                    IdlArrayLen::Generic(_) => {
                        return Err("generic array length is not supported".to_string())
                    }
                };
                let list = PyList::empty(py);
                for _ in 0..n {
                    let value = self.decode_type(py, cur, inner)?;
                    list.append(value).map_err(|e| e.to_string())?;
                }
                Ok(list.into_any())
            }
            IdlType::Defined { name, generics } => {
                if !generics.is_empty() {
                    return Err(format!("generic defined type '{name}' is not supported"));
                }
                self.decode_defined(py, cur, name)
            }
            IdlType::Generic(_) => Err("generic type parameter is not supported".to_string()),
            other => Err(format!("unsupported IDL type: {other:?}")),
        }
    }
}

/// The compiled extension module: `solana_anchor_events._solana_anchor_events`.
#[pymodule]
fn _solana_anchor_events(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<EventDecoder>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_reads_u64_le() {
        let value: u64 = 0x1122_3344_5566_7788;
        let bytes = value.to_le_bytes();
        let mut cur = Cursor::new(&bytes);
        let arr = cur.take_array::<8>().unwrap();
        assert_eq!(u64::from_le_bytes(arr), value);
        assert_eq!(cur.pos, 8);
        // Buffer is exhausted.
        assert!(cur.take(1).is_err());
    }

    #[test]
    fn cursor_reads_borsh_string() {
        let text = "pumpfun events";
        let mut buf = Vec::new();
        buf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        buf.extend_from_slice(text.as_bytes());

        let mut cur = Cursor::new(&buf);
        let len = read_u32_len(&mut cur).unwrap();
        assert_eq!(len, text.len());
        let raw = cur.take(len).unwrap();
        assert_eq!(std::str::from_utf8(raw).unwrap(), text);
        assert_eq!(cur.pos, buf.len());
    }

    #[test]
    fn pubkey_encodes_to_bs58() {
        // 32 zero bytes is the canonical default Pubkey: 32 '1' characters.
        let zeros = [0u8; 32];
        let mut cur = Cursor::new(&zeros);
        let arr = cur.take_array::<32>().unwrap();
        let encoded = pubkey_to_bs58(&arr);
        assert_eq!(encoded, "11111111111111111111111111111111");
        assert_eq!(encoded.len(), 32);

        // Arbitrary bytes round-trip through bs58.
        let mut bytes = [0u8; 32];
        bytes[0] = 0xDE;
        bytes[31] = 0xAD;
        let encoded = pubkey_to_bs58(&bytes);
        let decoded = bs58::decode(&encoded).into_vec().unwrap();
        assert_eq!(decoded, bytes.to_vec());
    }

    #[test]
    fn cursor_reads_borsh_vec() {
        // Vec<u8> = u32 length prefix + raw elements.
        let elems: [u8; 3] = [7, 8, 9];
        let mut buf = Vec::new();
        buf.extend_from_slice(&(elems.len() as u32).to_le_bytes());
        buf.extend_from_slice(&elems);

        let mut cur = Cursor::new(&buf);
        let len = read_u32_len(&mut cur).unwrap();
        assert_eq!(len, 3);
        let mut got = Vec::new();
        for _ in 0..len {
            got.push(cur.take(1).unwrap()[0]);
        }
        assert_eq!(got, vec![7, 8, 9]);
        assert_eq!(cur.pos, buf.len());
    }
}
