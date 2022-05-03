#![warn(missing_docs)]
//! crate to generate a boot.dat for sx pro from a payload for the switch

use binwrite::{BinWrite, WriterOption};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Result, Write};

#[derive(BinWrite, Debug, Default)]
#[binwrite(little)]
/// boot.dat header
/// typedef struct boot_dat_hdr
/// {
///     unsigned char ident[0x10];
///     unsigned char sha2_s2[0x20];
///     unsigned int s2_dst;
///     unsigned int s2_size;
///     unsigned int s2_enc;
///     unsigned char pad[0x10];
///     unsigned int s3_size;
///     unsigned char pad2[0x90];
///     unsigned char sha2_hdr[0x20];
/// } boot_dat_hdr_t;
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
    fn write_options<W: Write>(&self, writer: &mut W, options: &WriterOption) -> Result<()> {
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
    fn write_options<W: Write>(&self, writer: &mut W, options: &WriterOption) -> Result<()> {
        for item in &self.0 {
            BinWrite::write_options(item, writer, options)?;
        }
        Ok(())
    }
}

/// Get the crate version
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// generate a boot.dat given a payload
/// from https://gist.github.com/CTCaer/13c02c05daec9e674ba00ce5ac35f5be
/// `payload` is a byte array of the payload
pub fn generate_boot_dat(payload: &[u8]) -> Vec<u8> {
    let mut header = BootDatHeader::default();
    header.inner.ident = [
        0x43, 0x54, 0x43, 0x61, 0x65, 0x72, 0x20, 0x42, 0x4F, 0x4F, 0x54, 0x00,
    ];
    header.inner.vers = [0x56, 0x32, 0x2E, 0x35];

    let stage_2_sha256 = sha256_digest(payload);
    header.inner.sha2_s2 = Sha2(stage_2_sha256.try_into().unwrap());
    header.inner.s2_dst = 0x40010000;
    header.inner.s2_size = payload.len() as u32;

    let mut inner_serialized = vec![];
    header.inner.write(&mut inner_serialized).unwrap();

    let header_inner_sha256 = sha256_digest(inner_serialized.as_slice());
    header.sha2_hdr = Sha2(header_inner_sha256.try_into().unwrap());

    let mut serialized = vec![];
    header.write(&mut serialized).unwrap();

    serialized.extend_from_slice(payload);
    serialized
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
        let generated = super::generate_boot_dat(&[0xa, 0xb, 0xc]);
        let hash = super::sha256_digest(generated.as_slice());
        assert_eq!(
            hash[..],
            hex!("ce41209e72b8311fd5cf44be147ac0641a303eb3f9a2ed27c82ffb1e951a096f")
        );
    }
}
