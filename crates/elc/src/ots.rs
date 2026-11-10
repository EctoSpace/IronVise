//! Just enough OpenTimestamps to read a certificate's stamp offline.
//!
//! A certificate's `ots_proof_hex` is what the calendar returned for the
//! ledger tip: a *raw* timestamp, the operations that lead from the tip's 32
//! bytes to a commitment, then attestations. The old check looked for the
//! detached-file header, which a raw timestamp never has, so every stamp this
//! software made was reported as "format unrecognised" and `--require-anchor`
//! could not pass even after an upgrade.
//!
//! This walks the proof from the tip, as the OpenTimestamps reference client
//! does, and reports what it attests: calendars that promised to commit, or a
//! Bitcoin block height with the Merkle root that block must carry. Checking
//! that root against Bitcoin needs the network, and is left to `ots verify`;
//! [`detached_file`] writes the file that tool expects.
//!
//! Grammar, from python-opentimestamps: a timestamp is zero or more
//! `0xff`-prefixed branches then one final branch; a branch is either `0x00`
//! plus an attestation (8-byte tag, length-prefixed payload) or an operation
//! tag (binary operations carry a length-prefixed argument) followed by the
//! timestamp of the operation's result.

use sha2::{Digest, Sha256};

/// `\x00OpenTimestamps\x00\x00Proof\x00` plus eight magic bytes.
pub const FILE_MAGIC: &[u8] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const MAX_DEPTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attestation {
    /// A calendar's promise to commit this digest in a future block.
    Pending {
        calendar: String,
    },
    /// Committed in this Bitcoin block. `merkle_root` is the value the block
    /// header must carry, in the byte order block explorers display, when
    /// every operation on the path could be computed here.
    Bitcoin {
        height: u64,
        merkle_root: Option<String>,
    },
    Other {
        tag: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// `Some(digest)` for a detached `.ots` file (it names what it stamps);
    /// `None` for a raw timestamp, which is what certificates carry.
    pub file_digest: Option<Vec<u8>>,
    pub attestations: Vec<Attestation>,
}

impl Stamp {
    pub fn bitcoin(&self) -> Option<(u64, Option<&str>)> {
        self.attestations.iter().find_map(|a| match a {
            Attestation::Bitcoin {
                height,
                merkle_root,
            } => Some((*height, merkle_root.as_deref())),
            _ => None,
        })
    }

    pub fn calendars(&self) -> Vec<&str> {
        self.attestations
            .iter()
            .filter_map(|a| match a {
                Attestation::Pending { calendar } => Some(calendar.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// Parse a stamp over `message` (the ledger tip's 32 bytes). Accepts either a
/// raw timestamp or a detached `.ots` file.
pub fn parse(bytes: &[u8], message: &[u8]) -> Result<Stamp, String> {
    let mut r = Reader { b: bytes, i: 0 };
    let mut file_digest = None;
    let mut msg = Some(message.to_vec());
    if bytes.starts_with(FILE_MAGIC) {
        r.i = FILE_MAGIC.len();
        let major = r.varuint()?;
        if major != 1 {
            return Err(format!("unsupported .ots file version {major}"));
        }
        let op = r.byte()?;
        let len = match op {
            0x08 => 32, // sha256
            0x02 | 0x03 => 20,
            0x67 => 32,
            _ => return Err(format!("unknown file hash operation 0x{op:02x}")),
        };
        let digest = r.take(len)?.to_vec();
        msg = Some(digest.clone());
        file_digest = Some(digest);
    }
    let mut attestations = Vec::new();
    timestamp(&mut r, msg, &mut attestations, 0)?;
    if r.i != bytes.len() {
        return Err(format!(
            "{} trailing bytes after the timestamp",
            bytes.len() - r.i
        ));
    }
    Ok(Stamp {
        file_digest,
        attestations,
    })
}

/// A detached `.ots` file for `digest` (sha256) wrapping a raw timestamp, the
/// format `ots upgrade` and `ots verify` read.
pub fn detached_file(digest: &[u8; 32], raw_timestamp: &[u8]) -> Vec<u8> {
    let mut out = FILE_MAGIC.to_vec();
    out.push(0x01); // major version
    out.push(0x08); // sha256
    out.extend_from_slice(digest);
    out.extend_from_slice(raw_timestamp);
    out
}

/// The detached `.ots` file for a certificate's embedded stamp, for `ots
/// upgrade` and `ots verify`. Keep the upgraded file beside the certificate
/// and pass it back with `--ots`: writing it into `ots_proof_hex` would change
/// a field the signature covers.
pub fn detached_for(cert: &crate::EctoLedgerCertificate) -> Result<Vec<u8>, String> {
    let hex_stamp = cert
        .ots_proof_hex
        .as_deref()
        .ok_or("the certificate carries no OTS stamp")?;
    let raw = hex::decode(hex_stamp).map_err(|e| format!("ots_proof_hex is not hex: {e}"))?;
    if raw.starts_with(FILE_MAGIC) {
        return Ok(raw);
    }
    let tip: [u8; 32] = hex::decode(cert.ledger_tip_hash.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("ledger_tip_hash is not a 32-byte hex digest")?;
    parse(&raw, &tip)?;
    Ok(detached_file(&tip, &raw))
}

/// The raw timestamp inside a detached file, so an upgraded `.ots` can be
/// compared with, or read like, a certificate's stamp.
pub fn raw_timestamp(file: &[u8]) -> Option<&[u8]> {
    let rest = file.strip_prefix(FILE_MAGIC)?;
    // version (1) + op (1) + 32-byte sha256 digest
    (rest.len() > 34 && rest[0] == 0x01 && rest[1] == 0x08).then(|| &rest[34..])
}

fn timestamp(
    r: &mut Reader,
    msg: Option<Vec<u8>>,
    out: &mut Vec<Attestation>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("timestamp nested too deeply".into());
    }
    let mut tag = r.byte()?;
    while tag == 0xff {
        let t = r.byte()?;
        branch(r, t, msg.clone(), out, depth)?;
        tag = r.byte()?;
    }
    branch(r, tag, msg, out, depth)
}

fn branch(
    r: &mut Reader,
    tag: u8,
    msg: Option<Vec<u8>>,
    out: &mut Vec<Attestation>,
    depth: usize,
) -> Result<(), String> {
    if tag == 0x00 {
        let atag: [u8; 8] = r.take(8)?.try_into().unwrap();
        let payload = r.varbytes()?;
        let mut p = Reader { b: payload, i: 0 };
        out.push(match atag {
            TAG_PENDING => Attestation::Pending {
                calendar: String::from_utf8_lossy(p.varbytes()?).into_owned(),
            },
            TAG_BITCOIN => Attestation::Bitcoin {
                height: p.varuint()?,
                merkle_root: msg.map(|m| {
                    let mut be = m;
                    be.reverse();
                    hex::encode(be)
                }),
            },
            other => Attestation::Other {
                tag: hex::encode(other),
            },
        });
        return Ok(());
    }
    let next = match tag {
        0xf0 | 0xf1 => {
            let arg = r.varbytes()?.to_vec();
            msg.map(|m| {
                if tag == 0xf0 {
                    [m, arg].concat()
                } else {
                    [arg, m].concat()
                }
            })
        }
        0xf2 => msg.map(|mut m| {
            m.reverse();
            m
        }),
        0xf3 => msg.map(|m| hex::encode(m).into_bytes()),
        0x08 => msg.map(|m| Sha256::digest(&m).to_vec()),
        // sha1, ripemd160, keccak256: structurally fine; the digest along
        // this path is not computed here.
        0x02 | 0x03 | 0x67 => None,
        other => return Err(format!("unknown operation 0x{other:02x}")),
    };
    timestamp(r, next, out, depth + 1)
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.i).ok_or("stamp ends early")?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.i.checked_add(n).ok_or("length overflow")?;
        let s = self.b.get(self.i..end).ok_or("stamp ends early")?;
        self.i = end;
        Ok(s)
    }
    fn varuint(&mut self) -> Result<u64, String> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("varuint too long".into())
    }
    fn varbytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.varuint()?;
        if n > 8192 {
            return Err(format!("field of {n} bytes is larger than any stamp needs"));
        }
        self.take(n as usize)
    }
}

#[cfg(test)]
mod tests;
