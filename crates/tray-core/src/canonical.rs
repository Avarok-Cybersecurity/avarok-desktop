// SPDX-License-Identifier: MIT OR Apache-2.0
//! The bytes a publisher signs: the manifest's JSON, minus its `sig`, as deterministic CBOR
//! (RFC 8949 §4.2.1: shortest-form integers, definite lengths, map keys sorted by the bytes of
//! their encoding). Signing a re-encoding rather than the file means whitespace and key order in
//! the JSON never change what was signed, and the signer (in any language) needs no JSON quirks.

use ciborium::Value as Cbor;
use serde_json::Value as Json;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// Manifests carry integers only; a float has more than one encoding.
    Float,
    NotAnObject,
    Encode(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Float => f.write_str("a number is not an integer"),
            Self::NotAnObject => f.write_str("the manifest is not a JSON object"),
            Self::Encode(why) => write!(f, "it could not be encoded as CBOR: {why}"),
        }
    }
}

/// The deterministic CBOR of `object` with its top-level `omit` key left out.
pub fn signed_bytes(object: &Json, omit: &str) -> Result<Vec<u8>, CanonicalError> {
    let Json::Object(fields) = object else {
        return Err(CanonicalError::NotAnObject);
    };
    let kept = fields
        .iter()
        .filter(|(key, _)| key.as_str() != omit)
        .map(|(key, value)| Ok((key.as_str(), to_cbor(value)?)));
    let map = sorted_map(kept.collect::<Result<Vec<_>, CanonicalError>>()?)?;
    encode(&map)
}

fn to_cbor(value: &Json) -> Result<Cbor, CanonicalError> {
    Ok(match value {
        Json::Null => Cbor::Null,
        Json::Bool(b) => Cbor::Bool(*b),
        Json::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => Cbor::Integer(u.into()),
            (None, Some(i)) => Cbor::Integer(i.into()),
            (None, None) => return Err(CanonicalError::Float),
        },
        Json::String(s) => Cbor::Text(s.clone()),
        Json::Array(items) => Cbor::Array(items.iter().map(to_cbor).collect::<Result<_, _>>()?),
        Json::Object(fields) => sorted_map(
            fields
                .iter()
                .map(|(k, v)| Ok((k.as_str(), to_cbor(v)?)))
                .collect::<Result<Vec<_>, CanonicalError>>()?,
        )?,
    })
}

fn sorted_map(entries: Vec<(&str, Cbor)>) -> Result<Cbor, CanonicalError> {
    let mut keyed = entries
        .into_iter()
        .map(|(key, value)| {
            let key = Cbor::Text(key.to_owned());
            Ok((encode(&key)?, key, value))
        })
        .collect::<Result<Vec<_>, CanonicalError>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Cbor::Map(
        keyed.into_iter().map(|(_, k, v)| (k, v)).collect(),
    ))
}

fn encode(value: &Cbor) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| CanonicalError::Encode(e.to_string()))?;
    Ok(out)
}
