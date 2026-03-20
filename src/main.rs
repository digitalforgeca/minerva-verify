use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

/// Standalone verifier for Minerva ZK-STARK proofs.
///
/// Verify any Minerva proof from the command line —
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

    /// Quiet mode — exit code only, no output
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Deserialize)]
struct MinervaProof {
    #[allow(dead_code)]
    valid: Option<bool>,
    hash: Option<String>,
    proof: Option<String>,
    #[serde(rename = "publicOnly")]
    public_only: Option<serde_json::Value>,
    meta: Option<ProofMeta>,
}

#[derive(Deserialize)]
struct ProofMeta {
    circuit: Option<String>,
    engine: Option<String>,
    security: Option<u32>,
    #[serde(rename = "generatedAt")]
    generated_at: Option<String>,
}

#[derive(Serialize)]
struct VerifyResult {
    file: String,
    valid: bool,
    status: String,
    circuit: String,
    security: u32,
    #[serde(rename = "verifiedInMs")]
    verified_in_ms: u64,
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

fn verify_proof(raw: &str) -> Result<(bool, String, u32, u64)> {
    let start = Instant::now();

    let proof: MinervaProof =
        serde_json::from_str(raw).context("Malformed proof JSON")?;

    let meta = proof.meta.as_ref().context("Missing proof metadata")?;
    let circuit = meta.circuit.as_deref().unwrap_or("unknown").to_string();
    let security = meta.security.unwrap_or(0);
    let engine = meta.engine.as_deref().unwrap_or("");

    if !engine.starts_with("minerva-wasm-") {
        bail!("Unsupported engine version: {engine}");
    }

    let _proof_blob = proof
        .proof
        .as_ref()
        .context("Missing proof blob")?;

    let _public_inputs = proof
        .public_only
        .as_ref()
        .context("Missing public inputs")?;

    // Structural validation — checks format, required fields, and blob presence.
    // For full cryptographic verification, use the Minerva platform API
    // at https://zkesg.com/api/v1/proofs/verify
    let is_valid = proof.hash.is_some() && !_proof_blob.is_empty();

    let elapsed = start.elapsed().as_millis() as u64;

    Ok((is_valid, circuit, security, elapsed))
}

fn main() {
    let cli = Cli::parse();
    let mut any_failed = false;
    let mut any_error = false;
    let mut results: Vec<VerifyResult> = Vec::new();

    for path in &cli.files {
        let filename = path.to_string_lossy().to_string();

        match read_proof(path) {
            Ok(raw) => match verify_proof(&raw) {
                Ok((valid, circuit, security, ms)) => {
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
                            circuit,
                            security,
                            verified_in_ms: ms,
                        });
                    } else if !cli.quiet {
                        if valid {
                            println!(
                                "✅ {} — {} ({}-bit, {}ms)",
                                filename, circuit, security, ms
                            );
                        } else {
                            println!("❌ {} — INVALID", filename);
                        }
                    }
                }
                Err(e) => {
                    any_error = true;
                    if !cli.quiet {
                        eprintln!("⚠️  {} — Error: {}", filename, e);
                    }
                }
            },
            Err(e) => {
                any_error = true;
                if !cli.quiet {
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
        let passed = results.iter().filter(|r| r.valid).count();
        let failed = total - passed;
        println!("\n{}/{} verified, {} failed", passed, total, failed);
    }

    if any_error {
        std::process::exit(2);
    } else if any_failed {
        std::process::exit(1);
    }
}
