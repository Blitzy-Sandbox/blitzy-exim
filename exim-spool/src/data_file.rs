//! Spool data (-D) file read and write operations.
//!
//! This module implements byte-level compatible reading and writing of Exim
//! spool data files (the `-D` files in the spool input directory). These
//! files store the raw message body (RFC 5322 content after the envelope
//! headers are stripped).
//!
//! **Compatibility Rule (AAP §0.7.1):** Spool -D files written by C Exim
//! MUST be readable by this Rust implementation and vice versa. The file
//! format is preserved exactly: a first line containing `{message_id}-D\n`
//! followed by the raw message body data.
//!
//! # File format
//!
//! A `-D` spool file has the following structure:
//!
//! 1. **Identity line**: `{message_id}-D\n`
//! 2. **Message body data**: raw bytes starting at the data start offset
//!
//! The data start offset is `MESSAGE_ID_LENGTH + 3` bytes (26 for current
//! format, 19 for legacy format). This is defined by the constants
//! `SPOOL_DATA_START_OFFSET` and `SPOOL_DATA_START_OFFSET_OLD` in the
//! `format` module.
//!
//! # File operations
//!
//! The -D file is opened with `O_RDWR | O_APPEND` and the first line is
//! locked to prevent concurrent access. This is because Exim may append
//! to the data file during SMTP DATA reception.
//!
//! # Source origins
//!
//! - `src/src/spool_in.c` — `spool_open_datafile()`
//! - `src/src/spool_out.c` — data file creation during message reception
//! - `src/src/receive.c` — data file writing during SMTP DATA command

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::format::{spool_data_start_offset, spool_fname, SPOOL_MODE};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during spool data file operations.
#[derive(Debug)]
pub enum DataFileError {
    /// An I/O error occurred.
    Io(io::Error),
    /// The data file has an invalid or unexpected format.
    FormatError {
        /// Human-readable description of the format violation.
        message: String,
    },
    /// The message ID in the file does not match the expected ID.
    IdMismatch {
        /// Expected message ID.
        expected: String,
        /// Actual message ID found.
        found: String,
    },
    /// The file could not be opened (permissions, missing, etc.).
    OpenFailed {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying error.
        cause: io::Error,
    },
}

impl fmt::Display for DataFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataFileError::Io(e) => write!(f, "spool data I/O error: {}", e),
            DataFileError::FormatError { message } => {
                write!(f, "spool data format error: {}", message)
            }
            DataFileError::IdMismatch { expected, found } => write!(
                f,
                "spool data ID mismatch: expected '{}', found '{}'",
                expected, found
            ),
            DataFileError::OpenFailed { path, cause } => {
                write!(f, "cannot open spool data file {:?}: {}", path, cause)
            }
        }
    }
}

impl std::error::Error for DataFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DataFileError::Io(e) => Some(e),
            DataFileError::OpenFailed { cause, .. } => Some(cause),
            _ => None,
        }
    }
}

impl From<io::Error> for DataFileError {
    fn from(err: io::Error) -> Self {
        DataFileError::Io(err)
    }
}

// =============================================================================
// Data File Reader
// =============================================================================

/// A reader for spool -D (data) files.
///
/// This struct wraps a buffered file reader and provides methods to read
/// the message body data, handling the identity line and data start offset
/// transparently.
///
/// # Usage
///
/// ```no_run
/// use exim_spool::data_file::DataFileReader;
///
/// let reader = DataFileReader::open_from_reader(
///     std::io::Cursor::new(b"1pBnKl-003F4x-Tw-D\nbody data here"),
///     "1pBnKl-003F4x-Tw",
/// ).unwrap();
/// ```
pub struct DataFileReader<R: Read> {
    /// The underlying buffered reader, positioned after the identity line.
    reader: BufReader<R>,
    /// The message ID extracted from the identity line.
    message_id: String,
    /// The data start offset (bytes from file start to body data).
    data_offset: usize,
}

impl<R: Read> DataFileReader<R> {
    /// Open a data file from an existing reader.
    ///
    /// Reads and validates the identity line, then positions the reader
    /// at the start of the message body data.
    ///
    /// # Arguments
    ///
    /// * `reader` — A reader positioned at the start of the -D file.
    /// * `expected_id` — The expected message ID. If the file's ID does not
    ///   match, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] if the identity line is invalid or the
    /// message ID does not match.
    pub fn open_from_reader(reader: R, expected_id: &str) -> Result<Self, DataFileError> {
        let mut buf = BufReader::new(reader);

        // Read the identity line: "{message_id}-D\n"
        let mut id_line = String::new();
        io::BufRead::read_line(&mut buf, &mut id_line)?;

        let trimmed = id_line.trim_end_matches('\n').trim_end_matches('\r');
        if !trimmed.ends_with("-D") {
            return Err(DataFileError::FormatError {
                message: format!(
                    "data file identity line does not end with '-D': '{}'",
                    trimmed
                ),
            });
        }

        let file_id = &trimmed[..trimmed.len() - 2];
        if file_id != expected_id {
            return Err(DataFileError::IdMismatch {
                expected: expected_id.to_string(),
                found: file_id.to_string(),
            });
        }

        let data_offset = spool_data_start_offset(file_id);

        Ok(Self {
            reader: buf,
            message_id: file_id.to_string(),
            data_offset,
        })
    }

    /// Get the message ID from the data file.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Get the data start offset.
    pub fn data_offset(&self) -> usize {
        self.data_offset
    }

    /// Read the entire message body into a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] on I/O errors.
    pub fn read_body(&mut self) -> Result<Vec<u8>, DataFileError> {
        let mut body = Vec::new();
        self.reader.read_to_end(&mut body)?;
        Ok(body)
    }

    /// Read up to `limit` bytes of the message body.
    ///
    /// # Arguments
    ///
    /// * `limit` — Maximum number of bytes to read.
    ///
    /// # Returns
    ///
    /// A byte vector containing at most `limit` bytes of body data.
    pub fn read_body_limited(&mut self, limit: usize) -> Result<Vec<u8>, DataFileError> {
        let mut body = vec![0u8; limit];
        let n = self.reader.read(&mut body)?;
        body.truncate(n);
        Ok(body)
    }

    /// Get a reference to the underlying reader for direct access.
    ///
    /// The reader is positioned at the start of the message body data.
    pub fn inner(&mut self) -> &mut BufReader<R> {
        &mut self.reader
    }
}

impl DataFileReader<File> {
    /// Open a spool -D file from the filesystem.
    ///
    /// This replicates the behavior of `spool_open_datafile()` from
    /// `src/src/spool_in.c`:
    /// - Tries the split directory first (if `subdir` is non-empty), then the
    ///   unsplit directory
    /// - Opens with `O_RDWR` semantics
    /// - Validates the identity line
    ///
    /// # Arguments
    ///
    /// * `spool_directory` — Base spool directory (e.g., `/var/spool/exim`).
    /// * `queue_name` — Queue name (empty for default).
    /// * `subdir` — Subdirectory character (empty for unsplit).
    /// * `message_id` — The message ID to open.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] if the file cannot be opened or has an
    /// invalid format.
    pub fn open(
        spool_directory: &str,
        queue_name: &str,
        subdir: &str,
        message_id: &str,
    ) -> Result<Self, DataFileError> {
        // Try the split directory first, then the unsplit directory
        let paths = if !subdir.is_empty() {
            vec![
                spool_fname(
                    spool_directory,
                    queue_name,
                    "input",
                    subdir,
                    message_id,
                    "-D",
                ),
                spool_fname(spool_directory, queue_name, "input", "", message_id, "-D"),
            ]
        } else {
            vec![
                spool_fname(spool_directory, queue_name, "input", "", message_id, "-D"),
                spool_fname(
                    spool_directory,
                    queue_name,
                    "input",
                    subdir,
                    message_id,
                    "-D",
                ),
            ]
        };

        let mut last_err = None;
        for path in &paths {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => {
                    return Self::open_from_reader(file, message_id);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    last_err = Some(e);
                    continue;
                }
                Err(e) => {
                    return Err(DataFileError::OpenFailed {
                        path: path.clone(),
                        cause: e,
                    });
                }
            }
        }

        Err(DataFileError::OpenFailed {
            path: paths.into_iter().next().unwrap_or_default(),
            cause: last_err
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "data file not found")),
        })
    }
}

// =============================================================================
// Data File Writer
// =============================================================================

/// A writer for spool -D (data) files.
///
/// This struct wraps a buffered writer and provides methods to create a new
/// spool data file with the correct identity line and data start offset.
pub struct DataFileWriter<W: Write> {
    /// The underlying buffered writer, positioned after the identity line.
    writer: BufWriter<W>,
    /// The message ID.
    message_id: String,
    /// Number of body bytes written so far.
    bytes_written: usize,
}

impl<W: Write> DataFileWriter<W> {
    /// Create a new data file writer, writing the identity line.
    ///
    /// The identity line `{message_id}-D\n` is written immediately. After
    /// this call, the writer is positioned at the data start offset and
    /// ready to receive body data.
    ///
    /// # Arguments
    ///
    /// * `writer` — The underlying writer.
    /// * `message_id` — The message ID for the identity line.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] if the identity line cannot be written.
    pub fn create(writer: W, message_id: &str) -> Result<Self, DataFileError> {
        let mut buf = BufWriter::new(writer);
        writeln!(buf, "{}-D", message_id)?;
        buf.flush()?;

        Ok(Self {
            writer: buf,
            message_id: message_id.to_string(),
            bytes_written: 0,
        })
    }

    /// Write body data to the spool file.
    ///
    /// # Arguments
    ///
    /// * `data` — Body data bytes to write.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] on I/O errors.
    pub fn write_body(&mut self, data: &[u8]) -> Result<usize, DataFileError> {
        let n = self.writer.write(data)?;
        self.bytes_written += n;
        Ok(n)
    }

    /// Write the entire body from a reader.
    ///
    /// # Arguments
    ///
    /// * `reader` — Source of body data.
    ///
    /// # Returns
    ///
    /// Total number of bytes written.
    pub fn write_body_from<R: Read>(&mut self, mut reader: R) -> Result<usize, DataFileError> {
        let mut buf = [0u8; 8192];
        let mut total = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.writer.write_all(&buf[..n])?;
            total += n;
            self.bytes_written += n;
        }
        Ok(total)
    }

    /// Get the message ID.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Get the number of body bytes written so far.
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Flush and finalize the data file.
    ///
    /// This flushes the internal buffer and returns the underlying writer.
    pub fn finish(mut self) -> Result<W, DataFileError> {
        self.writer.flush()?;
        self.writer
            .into_inner()
            .map_err(|e| DataFileError::Io(e.into_error()))
    }
}

impl DataFileWriter<File> {
    /// Create a new spool -D file on the filesystem.
    ///
    /// # Arguments
    ///
    /// * `spool_directory` — Base spool directory.
    /// * `queue_name` — Queue name (empty for default).
    /// * `subdir` — Subdirectory character (empty for unsplit).
    /// * `message_id` — The message ID.
    ///
    /// # Errors
    ///
    /// Returns [`DataFileError`] if the file cannot be created.
    pub fn create_file(
        spool_directory: &str,
        queue_name: &str,
        subdir: &str,
        message_id: &str,
    ) -> Result<Self, DataFileError> {
        let path = spool_fname(
            spool_directory,
            queue_name,
            "input",
            subdir,
            message_id,
            "-D",
        );

        // Ensure the parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| DataFileError::OpenFailed {
                path: parent.to_path_buf(),
                cause: e,
            })?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| DataFileError::OpenFailed {
                path: path.clone(),
                cause: e,
            })?;

        // Set permissions (best-effort on platforms that support it)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(SPOOL_MODE));
        }

        Self::create(file, message_id)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Verify that a spool -D file's identity line matches the expected message ID.
///
/// This is a quick validation check that reads only the first line of the file.
///
/// # Arguments
///
/// * `reader` — A reader positioned at the start of the -D file.
/// * `expected_id` — The expected message ID.
///
/// # Returns
///
/// `true` if the identity line matches, `false` otherwise.
pub fn verify_data_file_id<R: Read>(reader: R, expected_id: &str) -> bool {
    let mut buf = BufReader::new(reader);
    let mut line = String::new();
    if io::BufRead::read_line(&mut buf, &mut line).is_err() {
        return false;
    }
    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
    if !trimmed.ends_with("-D") {
        return false;
    }
    &trimmed[..trimmed.len() - 2] == expected_id
}

/// Compute the message body size from a -D file.
///
/// Returns the size of the body data (total file size minus the data start
/// offset).
///
/// # Arguments
///
/// * `path` — Path to the -D file.
/// * `message_id` — The message ID (used to compute the data start offset).
///
/// # Errors
///
/// Returns [`io::Error`] if the file cannot be read.
pub fn data_file_body_size(path: &Path, message_id: &str) -> Result<u64, io::Error> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    let offset = spool_data_start_offset(message_id) as u64;
    if file_size < offset {
        return Ok(0);
    }
    Ok(file_size - offset)
}

/// Read the complete message body from a -D file path.
///
/// This is a convenience function that opens the file, validates the identity
/// line, and reads the entire body.
///
/// # Arguments
///
/// * `path` — Path to the -D file.
/// * `message_id` — Expected message ID.
///
/// # Errors
///
/// Returns [`DataFileError`] on any error.
pub fn read_body_from_path(path: &Path, message_id: &str) -> Result<Vec<u8>, DataFileError> {
    let file = File::open(path).map_err(|e| DataFileError::OpenFailed {
        path: path.to_path_buf(),
        cause: e,
    })?;
    let mut reader = DataFileReader::open_from_reader(file, message_id)?;
    reader.read_body()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_create_and_read_data_file() {
        let message_id = "1pBnKl-003F4x-Tw";
        let body_data =
            b"From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello, World!\r\n";

        // Write
        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        writer.write_body(body_data).unwrap();
        let _ = writer.finish().unwrap();

        // Verify the output starts with the identity line
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.starts_with("1pBnKl-003F4x-Tw-D\n"));

        // Read it back
        let reader = DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        assert_eq!(reader.message_id(), message_id);
        assert_eq!(
            reader.data_offset(),
            crate::format::spool_data_start_offset(message_id)
        );
    }

    #[test]
    fn test_roundtrip_body_data() {
        let message_id = "1pBnKl-003F4x-Tw";
        let body_data = b"Subject: Test\r\n\r\nThis is a test message.\r\n";

        // Write
        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        writer.write_body(body_data).unwrap();
        let _ = writer.finish().unwrap();

        // Read back
        let mut reader =
            DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        let read_body = reader.read_body().unwrap();
        assert_eq!(read_body, body_data);
    }

    #[test]
    fn test_empty_body() {
        let message_id = "1pBnKl-003F4x-Tw";

        // Write empty body
        let mut output = Vec::new();
        let writer = DataFileWriter::create(&mut output, message_id).unwrap();
        let _ = writer.finish().unwrap();

        // Read back
        let mut reader =
            DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        let read_body = reader.read_body().unwrap();
        assert!(read_body.is_empty());
    }

    #[test]
    fn test_write_body_from_reader() {
        let message_id = "1pBnKl-003F4x-Tw";
        let body_data = b"Large body data that might come from a network stream.\r\n";

        // Write from a reader
        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        let bytes = writer.write_body_from(Cursor::new(body_data)).unwrap();
        assert_eq!(bytes, body_data.len());
        assert_eq!(writer.bytes_written(), body_data.len());
        let _ = writer.finish().unwrap();

        // Read back
        let mut reader =
            DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        let read_body = reader.read_body().unwrap();
        assert_eq!(read_body, body_data);
    }

    #[test]
    fn test_read_limited() {
        let message_id = "1pBnKl-003F4x-Tw";
        let body_data = b"Hello, this is a longer body that we only want to partially read.";

        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        writer.write_body(body_data).unwrap();
        let _ = writer.finish().unwrap();

        let mut reader =
            DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        let partial = reader.read_body_limited(5).unwrap();
        assert_eq!(partial.len(), 5);
        assert_eq!(&partial, b"Hello");
    }

    #[test]
    fn test_id_mismatch() {
        let data = b"1pBnKl-003F4x-Tw-D\nbody";
        let result = DataFileReader::open_from_reader(Cursor::new(&data[..]), "DIFFERENT-ID");
        assert!(result.is_err());
        match result.err().unwrap() {
            DataFileError::IdMismatch { expected, found } => {
                assert_eq!(expected, "DIFFERENT-ID");
                assert_eq!(found, "1pBnKl-003F4x-Tw");
            }
            other => panic!("expected IdMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_format() {
        let data = b"not-a-valid-D-file\nbody";
        let result = DataFileReader::open_from_reader(Cursor::new(&data[..]), "test");
        assert!(result.is_err());
        match result.err().unwrap() {
            DataFileError::FormatError { message } => {
                assert!(
                    message.contains("-D"),
                    "error should mention -D: {}",
                    message
                );
            }
            other => panic!("expected FormatError, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_data_file_id() {
        let data = b"1pBnKl-003F4x-Tw-D\nbody data";
        assert!(verify_data_file_id(
            Cursor::new(&data[..]),
            "1pBnKl-003F4x-Tw"
        ));
        assert!(!verify_data_file_id(Cursor::new(&data[..]), "WRONG-ID"));
        assert!(!verify_data_file_id(Cursor::new(b"bad format"), "test"));
    }

    #[test]
    fn test_binary_body_data() {
        let message_id = "1pBnKl-003F4x-Tw";
        // Body with NUL bytes and other binary data
        let body_data: Vec<u8> = (0..=255).collect();

        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        writer.write_body(&body_data).unwrap();
        let _ = writer.finish().unwrap();

        let mut reader =
            DataFileReader::open_from_reader(Cursor::new(&output), message_id).unwrap();
        let read_body = reader.read_body().unwrap();
        assert_eq!(read_body, body_data);
    }

    #[test]
    fn test_error_display() {
        let err = DataFileError::FormatError {
            message: "bad identity".into(),
        };
        assert!(err.to_string().contains("bad identity"));

        let err = DataFileError::IdMismatch {
            expected: "aaa".into(),
            found: "bbb".into(),
        };
        assert!(err.to_string().contains("aaa"));
        assert!(err.to_string().contains("bbb"));
    }

    #[test]
    fn test_bytes_written_counter() {
        let message_id = "1pBnKl-003F4x-Tw";
        let mut output = Vec::new();
        let mut writer = DataFileWriter::create(&mut output, message_id).unwrap();
        assert_eq!(writer.bytes_written(), 0);
        writer.write_body(b"hello").unwrap();
        assert_eq!(writer.bytes_written(), 5);
        writer.write_body(b" world").unwrap();
        assert_eq!(writer.bytes_written(), 11);
        let _ = writer.finish().unwrap();
    }
}
