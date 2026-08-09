use std::io::{Cursor, Error, IoSlice, Result, Seek, SeekFrom, Write};

/// A wrapper around Cursor that checks the underlying buffer isn't exceeding a max size.
/// This is specifically needed to avoid borrow checker issues around being able to check the buf size.
pub struct LimitedCursor {
    inner: Cursor<Vec<u8>>,
    limit: u64,
}

impl LimitedCursor {
    pub fn new(limit: u64) -> Self {
        Self {
            inner: Cursor::new(vec![]),
            limit,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.inner.into_inner()
    }
}

impl Seek for LimitedCursor {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        // Underlying implementation doesn't seem to alloc on seek - just updates offsets.
        // So let's wait until there's a write() to check limits.
        self.inner.seek(pos)
    }

    fn stream_position(&mut self) -> Result<u64> {
        self.inner.stream_position()
    }
}

impl Write for LimitedCursor {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let length = self.inner.position() + buf.len() as u64;
        if length > self.limit {
            return Err(Error::other(
                format!(
                    "Write of {} bytes at position {} would exceed size limit {}",
                    buf.len(),
                    self.inner.position(),
                    self.limit
                ),
            ));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// A wrapper around Write that checks the underlying buffer isn't exceeding a max size.
/// This is specifically needed to avoid borrow checker issues around being able to check the buf size.
pub struct LimitedWrite<T>
where
    T: Write,
{
    inner: T,
    limit: u64,
}

impl<T> LimitedWrite<T>
where
    T: Write,
{
    pub fn new(inner: T, limit: u64) -> Self {
        Self { inner, limit }
    }

    pub fn remaining(&self) -> u64 {
        self.limit
    }

    /// Whether `len` more bytes fit in the remaining budget. Does NOT spend
    /// it: the budget is charged by [`charge`] for what the inner writer
    /// actually accepted, since a short write must not cost bytes that never
    /// reached the file (the zip unpack carries this budget across files, so
    /// an over-charge compounds and fails a legitimate paste early).
    fn check_limit(&self, len: u64) -> Result<()> {
        if len > self.limit {
            return Err(Error::other(
                format!(
                    "Write of {} bytes would exceed size limit {}",
                    len, self.limit
                ),
            ));
        }
        Ok(())
    }

    /// Spends `written` bytes of the budget. Saturating: check_limit has
    /// already refused anything larger, so this can only underflow if an inner
    /// writer reports writing more than it was given.
    fn charge(&mut self, written: u64) {
        self.limit = self.limit.saturating_sub(written);
    }
}

impl<T> Write for LimitedWrite<T>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.check_limit(buf.len() as u64)?;
        let written = self.inner.write(buf)?;
        self.charge(written as u64);
        Ok(written)
    }

    // Pass through all these in case inner has its own implementations:

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        // Checked against the total, charged for what writev actually took:
        // one writev commonly delivers only the first iovec or two.
        let total: u64 = bufs.iter().map(|buf| buf.len() as u64).sum();
        self.check_limit(total)?;
        let written = self.inner.write_vectored(bufs)?;
        self.charge(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        // write_all either delivers everything or errors, so the full length
        // is the honest charge here.
        self.check_limit(buf.len() as u64)?;
        self.inner.write_all(buf)?;
        self.charge(buf.len() as u64);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that accepts only `chunk` bytes per call, like a pipe or a
    /// short write to a file under pressure.
    struct ShortWriter {
        chunk: usize,
        written: Vec<u8>,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let take = buf.len().min(self.chunk);
            self.written.extend_from_slice(&buf[..take]);
            Ok(take)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// The budget must be charged for bytes that actually reached the writer,
    /// never for bytes it declined to take. Charging the full buffer on a
    /// short write over-spends, and since the zip unpack carries this budget
    /// across files (max_uncompressed_size_bytes = remaining()), the error
    /// compounds and fails a legitimate paste well under the real limit.
    #[test]
    fn a_short_write_only_charges_what_was_written() {
        let inner = ShortWriter { chunk: 4, written: Vec::new() };
        let mut limited = LimitedWrite::new(inner, 100);
        assert_eq!(limited.write(&[0u8; 10]).unwrap(), 4);
        assert_eq!(limited.remaining(), 96, "charged for bytes never written");
    }

    #[test]
    fn vectored_writes_charge_only_the_delivered_bytes() {
        let inner = ShortWriter { chunk: 3, written: Vec::new() };
        let mut limited = LimitedWrite::new(inner, 100);
        let a = [1u8; 5];
        let b = [2u8; 5];
        let bufs = [IoSlice::new(&a), IoSlice::new(&b)];
        let written = limited.write_vectored(&bufs).unwrap();
        assert_eq!(written, 3);
        assert_eq!(limited.remaining(), 97, "charged for every iovec offered");
    }

    /// The limit itself still has to bite — the fix must not turn it off.
    #[test]
    fn the_limit_still_refuses_an_oversized_write() {
        let inner = ShortWriter { chunk: 1024, written: Vec::new() };
        let mut limited = LimitedWrite::new(inner, 8);
        assert!(limited.write(&[0u8; 9]).is_err());
        assert!(limited.write_all(&[0u8; 9]).is_err());
        // Exactly the budget is fine, and exhausts it.
        assert!(limited.write_all(&[0u8; 8]).is_ok());
        assert_eq!(limited.remaining(), 0);
        assert!(limited.write(&[0u8; 1]).is_err());
    }

    #[test]
    fn limited_cursor_refuses_past_its_limit() {
        let mut cursor = LimitedCursor::new(4);
        assert!(cursor.write_all(b"abcd").is_ok());
        assert!(cursor.write_all(b"e").is_err());
        assert_eq!(cursor.into_inner(), b"abcd");
    }
}
