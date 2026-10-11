use std::path::PathBuf;

/// Errors produced by rex crates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Input exceeded a configured resource limit.
    #[error(
        "input is {size} bytes which exceeds the limit of {limit} bytes (raise with --max-size)"
    )]
    TooLarge {
        /// Actual size.
        size: u64,
        /// Limit.
        limit: u64,
    },
    /// The data could not be parsed as the expected format.
    #[error("parse error ({format}): {message}")]
    Parse {
        /// Format being parsed, e.g. "ELF", "DEX".
        format: &'static str,
        /// Human-readable message.
        message: String,
    },
    /// The input kind is not supported by the requested operation.
    #[error("unsupported input: {0}")]
    Unsupported(String),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Convenience constructor for parse errors.
    pub fn parse(format: &'static str, message: impl Into<String>) -> Self {
        Error::Parse {
            format,
            message: message.into(),
        }
    }
}

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
