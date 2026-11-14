//! Wire-format RDATA helpers (uncompressed, design section 4.8).

use super::RecordError;
use super::text::syntax;
use crate::name::TargetName;

/// The most octets RDATA can hold.
pub(crate) const MAX_RDATA: usize = 65_535;

/// A cursor over wire-format RDATA. Every read checks bounds.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn truncated(&self) -> RecordError {
        syntax(format!("the data ends early at octet {}", self.pos))
    }

    /// The octets not read yet.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], RecordError> {
        let slice = self
            .data
            .get(self.pos..self.pos + len)
            .ok_or_else(|| self.truncated())?;
        self.pos += len;
        Ok(slice)
    }

    /// Everything not read yet.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let slice = self.data.get(self.pos..).unwrap_or_default();
        self.pos = self.data.len();
        slice
    }

    pub(crate) fn u8(&mut self) -> Result<u8, RecordError> {
        match self.bytes(1)? {
            [b] => Ok(*b),
            _ => Err(self.truncated()),
        }
    }

    pub(crate) fn u16(&mut self) -> Result<u16, RecordError> {
        match self.bytes(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(self.truncated()),
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, RecordError> {
        match self.bytes(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(self.truncated()),
        }
    }

    /// One uncompressed domain name.
    pub(crate) fn name(&mut self) -> Result<TargetName, RecordError> {
        let rest = self.data.get(self.pos..).unwrap_or_default();
        let (name, used) =
            TargetName::from_wire_prefix(rest).map_err(|err| syntax(err.describe()))?;
        self.pos += used;
        Ok(name)
    }

    /// One character-string: a length octet and that many octets.
    pub(crate) fn character_string(&mut self) -> Result<&'a [u8], RecordError> {
        let len = self.u8()?;
        self.bytes(usize::from(len))
    }

    /// Fails unless everything was read.
    pub(crate) fn finish(&self) -> Result<(), RecordError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(syntax(format!(
                "{} unexpected octets after the end of the data",
                self.remaining()
            )))
        }
    }
}

/// Appends a 16-bit length prefix for `len` octets; fails above 65535.
pub(crate) fn push_len16(out: &mut Vec<u8>, len: usize) -> Result<(), RecordError> {
    let len = u16::try_from(len).map_err(|_| RecordError::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

/// Appends one character-string; fails above 255 octets.
pub(crate) fn push_character_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RecordError> {
    let len = u8::try_from(bytes.len()).map_err(|_| RecordError::TooLong)?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}
