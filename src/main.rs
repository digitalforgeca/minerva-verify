use anyhow::{Context, Result};
use clap::Parser;
use minerva_verify::{verify_proof_output, ProofOutput};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

/// Standalone verifier for Minerva ZK-STARK proofs.
///
/// Performs real cryptographic verification using Winterfell —
/// no account, no API key, no private data needed.
#[derive(Parser)]
#[command(name = "minerva-verify", version, about)]
struct Cli {
    /// Proof files to verify (use "-" for stdin)
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output JSON instead of human-readable text
    #[arg(long)]
    json: bool,

    /// Verbose mode — show detailed verification info
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode — exit code only, no output
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Serialize)]
struct VerifyResult {
    file: String,
    valid: bool,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    circuit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_at: Option<String>,
    #[serde(rename = "verifiedInMs")]
    verified_in_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn read_proof(path: &PathBuf) -> Result<String> {
    if path.to_str() == Some("-") {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))
    }
}

fn do_verify(raw: &str, verbose: bool) -> Result<(bool, Option<String>, Option<String>, u64)> {
    let start = Instant::now();

    let output: ProofOutput =
        serde_json::from_str(raw).context("Malformed proof JSON — expected ProofOutput format")?;

    if verbose {
        eprintln!(
            "  proof blob: {} bytes (encoded)",
            output.proof.len()
        );
        eprintln!(
            "  public inputs: {}",
            serde_json::to_string(&output.public_inputs).unwrap_or_default()
        );
        eprintln!(
            "  circuit gates: {}",
            output.circuit.gates.len()
        );
        if let Some(ref hash) = output.circuit_hash {
            eprintln!("  circuit hash: {}", hash);
        }
    }

    let is_valid = verify_proof_output(&output)?;

    let elapsed = start.elapsed().as_millis() as u64;

    Ok((
        is_valid,
        output.circuit_hash,
        output.generated_at,
        elapsed,
    ))
}

fn main() {
    let cli = Cli::parse();
    let mut any_failed = false;
    let mut any_error = false;
    let mut results: Vec<VerifyResult> = Vec::new();

    for path in &cli.files {
        let filename = path.to_string_lossy().to_string();

        if cli.verbose && !cli.quiet {
            eprintln!("Verifying: {}", filename);
        }

        match read_proof(path) {
            Ok(raw) => match do_verify(&raw, cli.verbose && !cli.quiet) {
                Ok((valid, circuit_hash, generated_at, ms)) => {
                    if !valid {
                        any_failed = true;
                    }

                    if cli.json {
                        results.push(VerifyResult {
                            file: filename,
                            valid,
                            status: if valid {
                                "verified".into()
                            } else {
                                "invalid".into()
                            },
                            circuit_hash,
                            generated_at,
                            verified_in_ms: ms,
                            error: None,
                        });
                    } else if !cli.quiet {
                        if valid {
                            println!("✅ {} — verified ({}ms)", filename, ms);
                        } else {
                            println!("❌ {} — INVALID ({}ms)", filename, ms);
                        }
                    }
                }
                Err(e) => {
                    any_error = true;
                    if cli.json {
                        results.push(VerifyResult {
                            file: filename.clone(),
                            valid: false,
                            status: "error".into(),
                            circuit_hash: None,
                            generated_at: None,
                            verified_in_ms: 0,
                            error: Some(format!("{}", e)),
                        });
                    } else if !cli.quiet {
                        eprintln!("⚠️  {} — Error: {}", filename, e);
                    }
                }
            },
            Err(e) => {
                any_error = true;
                if cli.json {
                    results.push(VerifyResult {
                        file: filename.clone(),
                        valid: false,
                        status: "error".into(),
                        circuit_hash: None,
                        generated_at: None,
                        verified_in_ms: 0,
                        error: Some(format!("{}", e)),
                    });
                } else if !cli.quiet {
                    eprintln!("⚠️  {} — {}", filename, e);
                }
            }
        }
    }

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&results).unwrap_or_default()
        );
    } else if !cli.quiet && cli.files.len() > 1 {
        let total = cli.files.len();
        let passed = results.len();
        let valid_count = results.iter().filter(|r| r.valid).count();
        // When not in json mode, results only has json entries — use counters
        let _ = passed;
        let verified = cli.files.len() - (if any_failed { 1 } else { 0 }) - (if any_error { 1 } else { 0 });
        let _ = verified;
        let _ = valid_count;
        println!("\n{} file(s) processed", total);
    }

    if any_error {
        std::process::exit(2);
    } else if any_failed {
        std::process::exit(1);
    }
}
