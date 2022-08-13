#![warn(missing_docs)]
//! crate to generate a boot.dat for sx pro from a payload for the switch

use binwrite::{BinWrite, WriterOption};
use conv::ValueFrom;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Formatter;
use std::io::Write;
use thiserror::Error;

#[derive(BinWrite, Debug, Default)]
#[binwrite(little)]
/// boot.dat header
// typedef struct boot_dat_hdr
// {
//     unsigned char ident[0x10];
//     unsigned char sha2_s2[0x20];
//     unsigned int s2_dst;
//     unsigned int s2_size;
//     unsigned int s2_enc;
//     unsigned char pad[0x10];
//     unsigned int s3_size;
//     unsigned char pad2[0x90];
//     unsigned char sha2_hdr[0x20];
// } boot_dat_hdr_t;
struct BootDatHeader {
    inner: BootDatInner,
    sha2_hdr: Sha2,
}

#[derive(BinWrite, Debug, Default)]
#[binwrite(little)]
struct BootDatInner {
    ident: [u8; 0xc],
    vers: [u8; 0x4],
    sha2_s2: Sha2,
    s2_dst: u32,
    s2_size: u32,
    s2_enc: u32,
    pad: [u8; 0x10],
    s3_size: u32,
    pad2: Pad2,
}

/// Error enum for this crate
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// Error during I/O operations
    IoError(String),
    /// Error while converting the hash
    HashError,
    /// Error while truncating lengths
    TruncationError,
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Error::IoError(s) => write!(fmt, "IO Error: {}", s),
            Error::HashError => write!(fmt, "Hash Error"),
            Error::TruncationError => write!(fmt, "Number Truncation Error"),
        }
    }
}

// Workaround because Default and BinWrite don't support arrays of this dimension
struct Pad2([u8; 0x90]);

impl Default for Pad2 {
    fn default() -> Self {
        Pad2([0; 0x90])
    }
}

impl fmt::Debug for Pad2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl BinWrite for Pad2 {
    fn write_options<W: Write>(
        &self,
        writer: &mut W,
        options: &WriterOption,
    ) -> std::io::Result<()> {
        for item in &self.0 {
            BinWrite::write_options(item, writer, options)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Sha2([u8; 0x20]);

impl fmt::Debug for Sha2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl BinWrite for Sha2 {
    fn write_options<W: Write>(
        &self,
        writer: &mut W,
        options: &WriterOption,
    ) -> std::io::Result<()> {
        for item in &self.0 {
            BinWrite::write_options(item, writer, options)?;
        }
        Ok(())
    }
}

/// Get the crate version
#[must_use]
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// generate a boot.dat given a payload
/// from <https://gist.github.com/CTCaer/13c02c05daec9e674ba00ce5ac35f5be>
/// but revisited to match <https://sx-boot-dat-creator.herokuapp.com/> which works for me
/// `payload` is a byte array of the payload
///
/// # Errors
/// Returns an Error if there are problem hashing or serializing
pub fn generate_boot_dat(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut header = BootDatHeader::default();
    header.inner.ident = [
        0x49, 0x6e, 0x73, 0x61, 0x6e, 0x65, 0x20, 0x42, 0x4F, 0x4F, 0x54, 0x00,
    ];
    header.inner.vers = [0x56, 0x31, 0x2E, 0x30];

    let stage_2_sha256 = sha256_digest(payload);
    header.inner.sha2_s2 = Sha2(stage_2_sha256.try_into().map_err(|_| Error::HashError)?);
    header.inner.s2_dst = 0x4001_0000;
    header.inner.s2_size = u32::value_from(payload.len()).map_err(|_| Error::TruncationError)?;

    let mut inner_serialized = vec![];
    header.inner.write(&mut inner_serialized)?;

    let header_inner_sha256 = sha256_digest(inner_serialized.as_slice());
    header.sha2_hdr = Sha2(
        header_inner_sha256
            .try_into()
            .map_err(|_| Error::HashError)?,
    );

    let mut serialized = vec![];
    header.write(&mut serialized)?;

    serialized.extend_from_slice(payload);
    Ok(serialized)
}

/// Calc sha256 for a byte array
fn sha256_digest(to_hash: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(to_hash);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    #[test]
    fn end_to_end_test() {
        let generated = super::generate_boot_dat(&[0xa, 0xb, 0xc]).unwrap();
        let hash = super::sha256_digest(generated.as_slice());
        assert_eq!(
            hash[..],
            hex!("6ce4c88e604d351b0e14bca7dbf135b3c8c44428718b704883599f285eed984e")
        );
    }
}
