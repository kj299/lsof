//! The data model — the Rust analog of the C structs you are porting. Prefer
//! owned, bounded types (`String`, `Vec`, enums) over the C habit of raw
//! pointers + length fields; that habit is where the bugs lived.

/// One parsed record. Replace the fields with your ported struct's shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub key: String,
    pub value: String,
}

impl Record {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}
