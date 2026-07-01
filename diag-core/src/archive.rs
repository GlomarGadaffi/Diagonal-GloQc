//! Raw archive — spec/diag-protocol.md §8.
//!
//! Append-only, lossless store of raw de-escaped message bytes, gzip
//! compressed. Deliberately dumb: no parsing, no filtering — anything
//! written here can be fully re-decoded later regardless of today's
//! decoder coverage (spec §7). Lowest legal sensitivity of any module in
//! this rewrite (spec §8): consumes a pre-existing container convention,
//! doesn't author one.
//!
//! [`ArchiveReader`] tolerates reading a file that's still being written
//! to (no finalizing gzip trailer yet — `ArchiveWriter::close` hasn't been
//! called): an `UnexpectedEof` mid-stream returns what decompressed
//! cleanly so far instead of erroring, since that's the normal state of
//! a live in-progress recording, not corruption. Matches how the vendored
//! qmdl reader this replaces handles the same live-recording case.

use std::io::{self, Read, Seek, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

pub struct ArchiveWriter<W: Write + Seek> {
    encoder: GzEncoder<W>,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            encoder: GzEncoder::new(writer, Compression::default()),
        }
    }

    /// Appends raw bytes as-is. Flushes immediately so `size()` reflects
    /// what's durably written after each call — matters for a caller
    /// tracking live-recording progress, not just a final total.
    pub fn write_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.encoder.write_all(bytes)?;
        self.encoder.flush()
    }

    /// Bytes written to the underlying writer so far (compressed size).
    pub fn size(&mut self) -> io::Result<u64> {
        self.encoder.get_mut().stream_position()
    }

    /// Finalizes the gzip stream and returns the final compressed size.
    pub fn close(self) -> io::Result<u64> {
        let mut inner = self.encoder.finish()?;
        inner.stream_position()
    }
}

pub struct ArchiveReader<R: Read> {
    decoder: GzDecoder<R>,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            decoder: GzDecoder::new(reader),
        }
    }

    /// Decompresses and returns everything written to the archive so far.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        match self.decoder.read_to_end(&mut buf) {
            Ok(_) => Ok(buf),
            // No finalizing trailer yet — a file still being recorded to,
            // not corruption. Return what decompressed cleanly.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(buf),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_a_single_write() {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(&mut buf);
        writer.write_raw(b"hello archive").unwrap();
        writer.close().unwrap();

        buf.set_position(0);
        let mut reader = ArchiveReader::new(buf);
        assert_eq!(reader.read_all().unwrap(), b"hello archive".to_vec());
    }

    #[test]
    fn round_trips_multiple_appended_writes_in_order() {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(&mut buf);
        writer.write_raw(b"first ").unwrap();
        writer.write_raw(b"second ").unwrap();
        writer.write_raw(b"third").unwrap();
        writer.close().unwrap();

        buf.set_position(0);
        let mut reader = ArchiveReader::new(buf);
        assert_eq!(reader.read_all().unwrap(), b"first second third".to_vec());
    }

    #[test]
    fn size_grows_monotonically_as_bytes_are_written() {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(&mut buf);
        let initial = writer.size().unwrap();
        writer.write_raw(&[0u8; 1024]).unwrap();
        let after_first = writer.size().unwrap();
        writer.write_raw(&[1u8; 1024]).unwrap();
        let after_second = writer.size().unwrap();

        assert!(after_first > initial);
        assert!(after_second > after_first);
    }

    #[test]
    fn output_is_actually_gzip_compressed() {
        let mut buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(&mut buf);
        writer.write_raw(&[0u8; 4096]).unwrap(); // trivially compressible
        writer.close().unwrap();

        assert!(buf.get_ref().len() < 4096);
        // gzip magic number
        assert_eq!(&buf.get_ref()[0..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn empty_archive_round_trips_to_empty_bytes() {
        let mut buf = Cursor::new(Vec::new());
        let writer: ArchiveWriter<&mut Cursor<Vec<u8>>> = ArchiveWriter::new(&mut buf);
        writer.close().unwrap();

        buf.set_position(0);
        let mut reader = ArchiveReader::new(buf);
        assert_eq!(reader.read_all().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn read_all_tolerates_a_file_still_being_written_no_trailer_yet() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut writer = ArchiveWriter::new(&mut buf);
            writer.write_raw(b"partial data, close() deliberately not called").unwrap();
            // writer dropped here without calling close() - no gzip
            // trailer written, simulating a file still being actively
            // recorded to when something tries to read it.
        }

        buf.set_position(0);
        let mut reader = ArchiveReader::new(buf);
        assert_eq!(
            reader.read_all().unwrap(),
            b"partial data, close() deliberately not called".to_vec()
        );
    }
}
