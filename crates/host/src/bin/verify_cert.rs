// Standalone IronVise Audit Certificate verifier.
//
// Usage: verify-cert [--strict] [--expected-key <hex>] [--require-anchor] <path-to-audit.elc>
//
// Performs six checks in order: Ed25519 signature, hash-chain structure,
// Merkle root and finding proofs, goal hash, OTS timestamp, enclave attestation
// (informational). The checks are `ectoledger_elc::verify::verify`, the one
// implementation shared with `ironvise verify-certificate` and the browser
// verifier; this file parses arguments and prints the report.
//
// ## Two modes, because they answer different questions
//
// The default is **inspection**: it reports what is inside the file and whether
// the file is internally consistent. An unsigned certificate passes, because an
// unsigned certificate is a real artifact that people hold and a verifier that
// refuses to look at one is not useful.
//
// What inspection does *not* establish is who issued it. Checks 2-4 are
// self-referential: the hash chain, the Merkle root and the goal hash are all
// computed from the file's own contents, so a forger who builds a certificate
// from scratch passes every one of them. Only the signature ties the document
// to a key, and only an expected key ties that key to anyone.
//
// An unsigned file must not print `CERTIFICATE VALID`: that would be true
// about the checks it ran and a misleading summary of what had been
// established, which is worse than either. The verdict line distinguishes
// them, and `--strict` refuses to pass a certificate whose issuer is unknown.
//
// Exit code: 0 = VALID, 1 = INVALID or error.

use ectoledger_elc::verify::{Requirements, verify};
use std::process;

#[cfg(feature = "enclave-remote")]
use coset::CborSerializable as _;

const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} [options] <path-to-audit.elc>\n\n\
         Verifies an IronVise audit certificate offline. No database, no\n\
         network, no configuration - everything it checks is inside the file.\n\n\
         By default this inspects: it reports what the file contains and whether\n\
         the file is internally consistent. Internal consistency is not issuer\n\
         authentication - the hash chain, Merkle root and goal hash are all\n\
         computed from the file's own contents, so a certificate forged from\n\
         scratch passes all three. Only a signature, checked against a key you\n\
         obtained elsewhere, says who issued it.\n\n\
         Exit codes:\n  \
           0  the certificate verifies\n  \
           1  it does not, or it could not be read\n\n\
         Options:\n  \
           --strict             require a signature that verifies; an unsigned\n  \
                                certificate fails instead of warning\n  \
           --expected-key HEX   require the signature to be by this ed25519\n  \
                                public key. Implies --strict. Obtain the key\n  \
                                out of band; a key read from the certificate\n  \
                                only tells you it signed itself\n  \
           --require-anchor     require a Bitcoin attestation in the OTS stamp.\n  \
                                A fresh stamp is a calendar's promise and does\n  \
                                not satisfy this\n  \
           --issuer HEX         require a countersignature by this installation\n  \
                                issuer key (`ironvise issuer-key show`). On\n  \
                                its own it satisfies --strict\n  \
           --ots FILE           read the stamp from this .ots file instead of\n  \
                                the certificate: how an upgraded stamp is\n  \
                                presented, since rewriting ots_proof_hex would\n  \
                                break the signature. It must stamp this tip\n  \
           --export-ots FILE    write the certificate's stamp as a .ots file\n  \
                                for `ots upgrade` and `ots verify`, then verify\n  \
           -h, --help           print this and exit 0\n  \
           -V, --version        print the version and exit 0"
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("verify-cert");

    // An explicit --help is a request that succeeded, so it goes to stdout and
    // exits 0. Lumping it in with "wrong number of arguments" meant the binary
    // the documentation tells you to hand an auditor answered `--help` with
    // exit 1 on stderr, and treated `--version` as a filename.
    if args.iter().skip(1).any(|a| a == "--help" || a == "-h") {
        println!("{}", usage(program));
        process::exit(0);
    }
    if args.iter().skip(1).any(|a| a == "--version" || a == "-V") {
        println!("verify-cert {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let mut req = Requirements {
        signature: false,
        expected_key: None,
        anchor: false,
        ots_file: None,
        issuer: None,
    };
    let mut export_ots: Option<String> = None;
    let mut path_arg: Option<String> = None;
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--strict" => req.signature = true,
            "--require-anchor" => req.anchor = true,
            "--ots" => {
                let Some(p) = rest.next() else {
                    eprintln!("{RED}ERROR:{RESET} --ots needs a path to a .ots file");
                    process::exit(1);
                };
                match std::fs::read(p) {
                    Ok(b) => req.ots_file = Some(b),
                    Err(e) => {
                        eprintln!("{RED}ERROR:{RESET} could not read {p}: {e}");
                        process::exit(1);
                    }
                }
            }
            "--export-ots" => {
                let Some(p) = rest.next() else {
                    eprintln!("{RED}ERROR:{RESET} --export-ots needs a path to write");
                    process::exit(1);
                };
                export_ots = Some(p.clone());
            }
            "--expected-key" => {
                let Some(key) = rest.next() else {
                    eprintln!("{RED}ERROR:{RESET} --expected-key needs a hex public key");
                    process::exit(1);
                };
                // Knowing which key to expect is the whole point; requiring a
                // signature is implied by having an opinion about whose it is.
                req.signature = true;
                req.expected_key = Some(key.trim().to_lowercase());
            }
            "--issuer" => {
                let Some(key) = rest.next() else {
                    eprintln!("{RED}ERROR:{RESET} --issuer needs a hex public key");
                    process::exit(1);
                };
                req.issuer = Some(key.trim().to_lowercase());
            }
            other if other.starts_with('-') => {
                eprintln!(
                    "{RED}ERROR:{RESET} unknown option {other}\n\n{}",
                    usage(program)
                );
                process::exit(1);
            }
            other => {
                if path_arg.replace(other.to_string()).is_some() {
                    eprintln!(
                        "{RED}ERROR:{RESET} more than one certificate given\n\n{}",
                        usage(program)
                    );
                    process::exit(1);
                }
            }
        }
    }

    let Some(path_arg) = path_arg else {
        eprintln!("{}", usage(program));
        process::exit(1);
    };
    let path = std::path::Path::new(&path_arg);
    let cert = match ectoledger::certificate::read_certificate_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{RED}ERROR:{RESET} Could not read certificate: {e}");
            process::exit(1);
        }
    };

    if let Some(out) = &export_ots {
        match ectoledger_elc::ots::detached_for(&cert)
            .and_then(|b| std::fs::write(out, b).map_err(|e| e.to_string()))
        {
            Ok(()) => println!(
                "Wrote the stamp to {out}. Once a block confirms it: `ots upgrade {out}`, \
                 then `verify-cert --ots {out} <certificate>`."
            ),
            Err(e) => {
                eprintln!("{RED}ERROR:{RESET} could not export the stamp: {e}");
                process::exit(1);
            }
        }
    }
    let report = verify(&cert, &req);
    print!("{}", report.render_checks(true));
    #[cfg(feature = "enclave-remote")]
    print_cose_envelope(&cert);
    println!();
    println!("{}", report.render_verdict(true));
    process::exit(if report.is_valid() { 0 } else { 1 });
}

/// For remote hardware enclaves, report whether the raw attestation parses as a
/// COSE-Sign1 envelope. Informational, like the enclave check it follows, and
/// feature-gated because it needs `coset`, which the shared verifier does not.
#[cfg(feature = "enclave-remote")]
fn print_cose_envelope(cert: &ectoledger::certificate::EctoLedgerCertificate) {
    use ectoledger::enclave::runtime::EnclaveLevel;
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    let Some(att) = &cert.enclave_attestation else {
        return;
    };
    if att.level != EnclaveLevel::RemoteHardwareEnclave {
        return;
    }
    let Some(hex_blob) = &att.raw_attestation_hex else {
        return;
    };
    match hex::decode(hex_blob) {
        Ok(raw) => match coset::CoseSign1::from_slice(&raw) {
            Ok(_) => println!("     {GREEN}COSE-Sign1 envelope parsed successfully{RESET}"),
            Err(e) => println!(
                "     {YELLOW}COSE-Sign1 parse warning{RESET}: {} (may be a non-COSE format)",
                e
            ),
        },
        Err(e) => println!(
            "     {YELLOW}Could not decode raw_attestation_hex{RESET}: {}",
            e
        ),
    }
}
