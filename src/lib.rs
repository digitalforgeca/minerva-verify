//! # minerva-verify
//!
//! Standalone open-source verifier for Minerva ZK-STARK proofs.
//!
//! Performs real cryptographic verification using the Winterfell STARK library.
//! No account, API key, or private data needed — just the proof JSON.
//!
//! ## Library usage
//!
//! ```rust,no_run
//! use minerva_verify::verify_proof;
//!
//! let proof_json = std::fs::read_to_string("proof.json").unwrap();
//! let output: minerva_verify::ProofOutput = serde_json::from_str(&proof_json).unwrap();
//!
//! let public_inputs_json = serde_json::to_string(&output.public_inputs).unwrap();
//! let circuit_json = serde_json::to_string(&output.circuit).unwrap();
//!
//! match verify_proof(&output.proof, &public_inputs_json, &circuit_json) {
//!     Ok(true)  => println!("Valid proof"),
//!     Ok(false) => println!("Invalid proof"),
//!     Err(e)    => eprintln!("Error: {}", e),
//! }
//! ```

pub mod air;
pub mod types;
pub mod verify;

// Re-exports for convenient library use
pub use types::{Circuit, Gate, ProofOutput, PublicInputs, VerificationHints};
pub use verify::{verify_proof, verify_proof_output, verify_proof_with_hints};
