//! `prove-audit` remains a recognized command so existing callers get an
//! actionable error. SP1 proving was withdrawn from 0.8 because its dependency
//! graph contains crypto-bigint 0.5.5 (RUSTSEC-2026-0387). Certificate schemas
//! still preserve previously embedded proofs; offline verification is unchanged.

pub const UNAVAILABLE: &str = "prove-audit: SP1 ZK proving is unavailable in IronVise 0.8.\n\n\
    Its upstream dependencies are affected by RUSTSEC-2026-0387.\n\
    The experimental `zk` build feature has been removed.\n\n\
    For verifiable audit provenance, export a standard certificate:\n\
      ironvise report --format certificate --output audit.elc <session>";
