// Winterfell ZK-STARK proof verification for Minerva.
//
// This module performs real cryptographic verification by:
// 1. Deserializing the Winterfell proof from base64
// 2. Reconstructing public inputs from the circuit + public input JSON
// 3. Running Winterfell's verify() with the reconstructed AIR
//
// No prover code, no trace generation, no private data needed.

use crate::air::{MinervaAir, MinervaPublicInputs, CIRCUIT_COL_OFFSET};
use crate::types::{Circuit, Gate, VerificationHints};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
    Proof,
};

use base64::{prelude::BASE64_STANDARD, Engine};

/// Number of bits used for range decomposition in gt/lt gates.
pub const RANGE_DECOMP_BITS: usize = 64;

/// Returns the auxiliary column name for the diff column of a gt/lt gate.
pub fn diff_col_name(gate_idx: usize) -> String {
    format!("__diff_{}", gate_idx)
}

/// Returns the auxiliary column name for a bit column of a gt/lt gate.
pub fn bit_col_name(gate_idx: usize, bit: usize) -> String {
    format!("__bit_{}_{}", gate_idx, bit)
}

/// Collect gate output variable names (Add/Mul result columns).
pub fn gate_output_vars(circuit: &Circuit) -> HashSet<String> {
    let mut outputs = HashSet::new();
    for gate in &circuit.gates {
        match gate {
            Gate::Add { result, .. } | Gate::Multiply { result, .. } => {
                outputs.insert(result.clone());
            }
            _ => {}
        }
    }
    outputs
}

/// Convert a JSON value to a Winterfell `BaseElement`.
///
/// - Numbers: converted directly to u128
/// - Strings: SHA-256 hashed, first 8 bytes taken as u64
/// - Booleans: 0 or 1
/// - Other: zero
pub fn json_value_to_field_element(value: &serde_json::Value) -> Result<BaseElement> {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(v) = n.as_u64() {
                Ok(BaseElement::new(v as u128))
            } else if let Some(v) = n.as_f64() {
                Ok(BaseElement::new(v as u128))
            } else {
                Err(anyhow::anyhow!("Invalid number"))
            }
        }
        serde_json::Value::String(s) => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(s.as_bytes());
            let hash = h.finalize();
            let v = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            Ok(BaseElement::new(v as u128))
        }
        serde_json::Value::Bool(b) => Ok(BaseElement::new(if *b { 1 } else { 0 })),
        _ => Ok(BaseElement::ZERO),
    }
}

/// Extract a u128 value for a variable from the public inputs JSON.
/// Returns 0 if the variable is not found or cannot be parsed.
fn get_pub_value(public_map: &serde_json::Value, name: &str) -> u128 {
    if let serde_json::Value::Object(ref map) = public_map {
        if let Some(v) = map.get(name) {
            return match v {
                serde_json::Value::Number(n) => n
                    .as_u64()
                    .map(|x| x as u128)
                    .or_else(|| n.as_f64().map(|x| x as u128))
                    .unwrap_or(0),
                _ => 0,
            };
        }
    }
    0
}

/// Verify a Minerva ZK-STARK proof.
///
/// # Arguments
/// * `proof_string` — the proof blob (must start with "WINTERFELL_PROOF_" followed by base64)
/// * `public_inputs_json` — JSON string of the public inputs map
/// * `circuit_json` — JSON string of the circuit definition
///
/// # Returns
/// * `Ok(true)` if verification passes
/// * `Ok(false)` if verification fails (proof is invalid)
/// * `Err(...)` if there's a deserialization or format error
///
/// **Note:** This function reconstructs boundary assertions from public inputs only.
/// If the circuit has gt/lt gates with private operands, use [`verify_proof_with_hints`]
/// instead (or pass a [`ProofOutput`] to [`verify_proof_output`]).
pub fn verify_proof(
    proof_string: &str,
    public_inputs_json: &str,
    circuit_json: &str,
) -> Result<bool> {
    verify_proof_inner(proof_string, public_inputs_json, circuit_json, None)
}

/// Verify a Minerva ZK-STARK proof using verification hints.
///
/// Hints provide the variable names and initial values that the verifier needs
/// when gt/lt gates reference private inputs. The prover embeds these in the
/// `ProofOutput.verification_hints` field.
pub fn verify_proof_with_hints(
    proof_string: &str,
    public_inputs_json: &str,
    circuit_json: &str,
    hints: &VerificationHints,
) -> Result<bool> {
    verify_proof_inner(proof_string, public_inputs_json, circuit_json, Some(hints))
}

/// Verify a [`ProofOutput`] directly — the recommended entry point.
///
/// Automatically uses verification hints when present.
pub fn verify_proof_output(output: &crate::types::ProofOutput) -> Result<bool> {
    let public_inputs_json = serde_json::to_string(&output.public_inputs)
        .context("Failed to serialize public inputs")?;
    let circuit_json = serde_json::to_string(&output.circuit)
        .context("Failed to serialize circuit")?;
    verify_proof_inner(
        &output.proof,
        &public_inputs_json,
        &circuit_json,
        output.verification_hints.as_ref(),
    )
}

fn verify_proof_inner(
    proof_string: &str,
    public_inputs_json: &str,
    circuit_json: &str,
    hints: Option<&VerificationHints>,
) -> Result<bool> {
    if !proof_string.starts_with("WINTERFELL_PROOF_") {
        return Err(anyhow::anyhow!(
            "Invalid proof format: missing WINTERFELL_PROOF_ prefix"
        ));
    }
    let b64_part = &proof_string[17..];
    let proof_bytes =
        BASE64_STANDARD
            .decode(b64_part)
            .map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))?;
    let proof = Proof::from_bytes(&proof_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proof: {:?}", e))?;

    let trace_width = proof.context.trace_info().width();

    let pub_inputs = if let Some(hints) = hints {
        build_pub_inputs_from_hints(hints, circuit_json, trace_width)?
    } else {
        reconstruct_pub_inputs(public_inputs_json, circuit_json, trace_width)?
    };

    let acceptable_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    let result = winterfell::verify::<
        MinervaAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &acceptable_opts);

    match result {
        Ok(()) => Ok(true),
        Err(_e) => Ok(false),
    }
}

/// Build `MinervaPublicInputs` directly from verification hints.
///
/// The hints contain the exact variable names and initial values that the prover
/// used, so we don't need to reconstruct anything — just convert to `BaseElement`.
fn build_pub_inputs_from_hints(
    hints: &VerificationHints,
    circuit_json: &str,
    trace_width: usize,
) -> Result<MinervaPublicInputs> {
    let circuit: Circuit =
        serde_json::from_str(circuit_json).context("Failed to parse circuit JSON")?;

    let mut initial_values: Vec<BaseElement> = hints
        .initial_values
        .iter()
        .map(|&v| BaseElement::new(v))
        .collect();

    // Pad if trace_width > hints length
    while initial_values.len() < trace_width {
        initial_values.push(BaseElement::ZERO);
    }

    let mut variable_names = hints.variable_names.clone();
    while variable_names.len() < trace_width {
        variable_names.push(format!("__pad_{}", variable_names.len()));
    }

    Ok(MinervaPublicInputs {
        initial_values,
        variable_names,
        circuit,
    })
}

/// Reconstruct `MinervaPublicInputs` from JSON for verification.
///
/// Replicates the exact column ordering that the prover's `TraceGenerator` produces:
/// 1. Public inputs (sorted by key)
/// 2. Private inputs (inferred from gate operands, sorted)
/// 3. Gate output variables (Add/Mul result cols)
/// 4. Aux columns for gt/lt gates: __diff_N, __bit_N_0..63
///
/// For __diff_N columns: compute the expected diff from public inputs and
/// add a boundary assertion value so the verifier can check it.
fn reconstruct_pub_inputs(
    public_inputs_json: &str,
    circuit_json: &str,
    trace_width: usize,
) -> Result<MinervaPublicInputs> {
    let public_map: serde_json::Value =
        serde_json::from_str(public_inputs_json).context("Failed to parse public inputs JSON")?;
    let circuit: Circuit =
        serde_json::from_str(circuit_json).context("Failed to parse circuit JSON")?;

    let gate_outputs = gate_output_vars(&circuit);

    // Replicate TraceGenerator's variable_map ordering
    let mut variable_map: HashMap<String, usize> = HashMap::new();
    let mut next_col: usize = 0;

    // 1. Public inputs (sorted)
    if let serde_json::Value::Object(ref map) = public_map {
        let mut pub_keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        pub_keys.sort();
        for name in pub_keys {
            if !variable_map.contains_key(name) {
                variable_map.insert(name.to_string(), next_col);
                next_col += 1;
            }
        }
    }

    // 2. Infer private inputs from gate operands (sorted)
    {
        let mut private_names: Vec<String> = Vec::new();
        for gate in &circuit.gates {
            let (left, right) = match gate {
                Gate::Add { left, right, .. }
                | Gate::Multiply { left, right, .. }
                | Gate::Equal { left, right }
                | Gate::HashEqual { left, right }
                | Gate::GreaterThan { left, right }
                | Gate::LessThan { left, right } => (left.as_str(), right.as_str()),
            };
            for name in [left, right] {
                if !variable_map.contains_key(name) && !gate_outputs.contains(name) {
                    if !private_names.contains(&name.to_string()) {
                        private_names.push(name.to_string());
                    }
                }
            }
        }
        private_names.sort();
        for name in private_names {
            if !variable_map.contains_key(&name) {
                variable_map.insert(name, next_col);
                next_col += 1;
            }
        }
    }

    // 3. Gate output columns (Add/Mul)
    for gate in &circuit.gates {
        match gate {
            Gate::Add { result, .. } | Gate::Multiply { result, .. } => {
                if !variable_map.contains_key(result) {
                    variable_map.insert(result.clone(), next_col);
                    next_col += 1;
                }
            }
            _ => {}
        }
    }

    // 4. Auxiliary columns for gt/lt gates
    for (gate_idx, gate) in circuit.gates.iter().enumerate() {
        match gate {
            Gate::GreaterThan { .. } | Gate::LessThan { .. } => {
                let diff_name = diff_col_name(gate_idx);
                if !variable_map.contains_key(&diff_name) {
                    variable_map.insert(diff_name, next_col);
                    next_col += 1;
                }
                for bit in 0..RANGE_DECOMP_BITS {
                    let bit_name = bit_col_name(gate_idx, bit);
                    if !variable_map.contains_key(&bit_name) {
                        variable_map.insert(bit_name, next_col);
                        next_col += 1;
                    }
                }
            }
            _ => {}
        }
    }

    let circuit_width = next_col.max(1);
    let expected_wf_width = circuit_width + CIRCUIT_COL_OFFSET;

    // Build initial_values
    let mut initial_values = vec![BaseElement::ZERO; expected_wf_width];

    // Public input values
    if let serde_json::Value::Object(ref map) = public_map {
        for (name, value) in map.iter() {
            if let Some(&circuit_col) = variable_map.get(name) {
                if !gate_outputs.contains(name) {
                    let wf_col = circuit_col + CIRCUIT_COL_OFFSET;
                    if wf_col < expected_wf_width {
                        initial_values[wf_col] =
                            json_value_to_field_element(value).unwrap_or(BaseElement::ZERO);
                    }
                }
            }
        }
    }

    // For gt/lt gates: compute expected diff and bit values from public inputs.
    for (gate_idx, gate) in circuit.gates.iter().enumerate() {
        let diff_val_opt: Option<u64> = match gate {
            Gate::GreaterThan { left, right } => {
                let a = get_pub_value(&public_map, left);
                let b = get_pub_value(&public_map, right);
                if a > b {
                    Some((a - b - 1) as u64)
                } else {
                    None
                }
            }
            Gate::LessThan { left, right } => {
                let a = get_pub_value(&public_map, left);
                let b = get_pub_value(&public_map, right);
                if b > a {
                    Some((b - a - 1) as u64)
                } else {
                    None
                }
            }
            _ => continue,
        };

        if let Some(diff_val) = diff_val_opt {
            // Assert diff column
            let diff_name = diff_col_name(gate_idx);
            if let Some(&circuit_col) = variable_map.get(&diff_name) {
                let wf_col = circuit_col + CIRCUIT_COL_OFFSET;
                if wf_col < expected_wf_width {
                    initial_values[wf_col] = BaseElement::new(diff_val as u128);
                }
            }
            // Assert all bit columns
            for bit in 0..RANGE_DECOMP_BITS {
                let bit_val = (diff_val >> bit) & 1;
                let bit_name = bit_col_name(gate_idx, bit);
                if let Some(&circuit_col) = variable_map.get(&bit_name) {
                    let wf_col = circuit_col + CIRCUIT_COL_OFFSET;
                    if wf_col < expected_wf_width {
                        initial_values[wf_col] = BaseElement::new(bit_val as u128);
                    }
                }
            }
        }
        // If diff_val_opt is None (invalid comparison), initial_values remain 0.
        // The proof will fail because the prover's trace values won't match.
    }

    // Pad if trace_width > expected
    while initial_values.len() < trace_width {
        initial_values.push(BaseElement::ZERO);
    }

    // Build variable_names: counter first, then circuit cols by index
    let mut pairs: Vec<(String, usize)> = variable_map
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    pairs.sort_by_key(|(_, idx)| *idx);
    let mut variable_names = vec!["__counter".to_string()];
    variable_names.extend(pairs.into_iter().map(|(n, _)| n));
    while variable_names.len() < trace_width {
        variable_names.push(format!("__pad_{}", variable_names.len()));
    }

    Ok(MinervaPublicInputs {
        initial_values,
        variable_names,
        circuit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::StarkField;

    #[test]
    fn test_json_value_to_field_element_number() {
        let val = serde_json::json!(42);
        let elem = json_value_to_field_element(&val).unwrap();
        assert_eq!(elem.as_int(), 42);
    }

    #[test]
    fn test_json_value_to_field_element_bool() {
        assert_eq!(
            json_value_to_field_element(&serde_json::json!(true))
                .unwrap()
                .as_int(),
            1
        );
        assert_eq!(
            json_value_to_field_element(&serde_json::json!(false))
                .unwrap()
                .as_int(),
            0
        );
    }

    #[test]
    fn test_json_value_to_field_element_string() {
        // Strings get SHA-256 hashed - just verify it doesn't panic
        let val = serde_json::json!("hello");
        let elem = json_value_to_field_element(&val).unwrap();
        assert_ne!(elem.as_int(), 0);
    }

    #[test]
    fn test_gate_output_vars() {
        let circuit = Circuit {
            gates: vec![
                Gate::Add {
                    left: "a".into(),
                    right: "b".into(),
                    result: "sum".into(),
                },
                Gate::Equal {
                    left: "x".into(),
                    right: "y".into(),
                },
            ],
        };
        let outputs = gate_output_vars(&circuit);
        assert!(outputs.contains("sum"));
        assert!(!outputs.contains("a"));
        assert!(!outputs.contains("x"));
    }

    #[test]
    fn test_diff_col_name() {
        assert_eq!(diff_col_name(0), "__diff_0");
        assert_eq!(diff_col_name(3), "__diff_3");
    }

    #[test]
    fn test_bit_col_name() {
        assert_eq!(bit_col_name(0, 5), "__bit_0_5");
        assert_eq!(bit_col_name(2, 63), "__bit_2_63");
    }

    #[test]
    fn test_invalid_proof_prefix() {
        assert!(verify_proof("BAD_abc", "{}", r#"{"gates":[]}"#).is_err());
    }

    #[test]
    fn test_reconstruct_pub_inputs_basic() {
        let pub_json = r#"{"a": 5, "b": 3}"#;
        let circuit_json =
            r#"{"gates":[{"type":"add","left":"a","right":"b","result":"sum"}]}"#;
        // trace_width = 4 (counter + a + b + sum)
        let result = reconstruct_pub_inputs(pub_json, circuit_json, 4);
        assert!(result.is_ok());
        let pi = result.unwrap();
        assert_eq!(pi.variable_names[0], "__counter");
        assert!(pi.variable_names.contains(&"a".to_string()));
        assert!(pi.variable_names.contains(&"b".to_string()));
    }
}
