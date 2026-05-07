// Data types for Minerva ZK-STARK proof verification.
// Verification-only subset of Minerva data types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Public inputs that are included in the proof verification.
/// These values are visible to verifiers and constrain the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    #[serde(flatten)]
    pub data: BTreeMap<String, serde_json::Value>,
}

/// Circuit gate types supported by the proof system.
/// Each gate represents a different constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Gate {
    /// Equality constraint: left == right
    #[serde(rename = "eq")]
    Equal { left: String, right: String },

    /// Greater than constraint: left > right
    #[serde(rename = "gt")]
    GreaterThan { left: String, right: String },

    /// Hash equality constraint: left == hash(right)
    #[serde(rename = "hash_eq")]
    HashEqual { left: String, right: String },

    /// Less than constraint: left < right
    #[serde(rename = "lt")]
    LessThan { left: String, right: String },

    /// Addition constraint: result = left + right
    #[serde(rename = "add")]
    Add {
        left: String,
        right: String,
        result: String,
    },

    /// Multiplication constraint: result = left * right
    #[serde(rename = "mul")]
    Multiply {
        left: String,
        right: String,
        result: String,
    },
}

/// Circuit definition containing all constraint gates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    pub gates: Vec<Gate>,
}

/// Verification hints — boundary assertion data for standalone verifiers.
///
/// When a circuit uses private inputs (e.g. gt/lt gates with a private operand),
/// the verifier cannot reconstruct boundary assertions from public inputs alone.
/// These hints provide the variable names and initial values that the verifier
/// needs to reconstruct the AIR public inputs without the prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationHints {
    /// Variable names in column order: `["__counter", "a", "b", "sum", ...]`
    pub variable_names: Vec<String>,
    /// Initial values at step 0 as u128 field elements, one per column.
    pub initial_values: Vec<u128>,
}

/// Generated proof output — the standard format for Minerva proofs.
/// This is what the verifier accepts as input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOutput {
    /// Base64-encoded Winterfell proof with "WINTERFELL_PROOF_" prefix
    pub proof: String,
    /// Public inputs used in the proof
    pub public_inputs: PublicInputs,
    /// Circuit definition (constraint gates)
    pub circuit: Circuit,
    /// SHA-256 hash of the circuit definition (optional)
    pub circuit_hash: Option<String>,
    /// Timestamp of proof generation (optional)
    pub generated_at: Option<String>,
    /// Verification hints for standalone verifiers (optional, but required
    /// for proofs with private gt/lt operands).
    pub verification_hints: Option<VerificationHints>,
}
