// Winterfell AIR (Algebraic Intermediate Representation) for Minerva.
//
// This must match the AIR used by the Minerva proof engine exactly.
// Any divergence would cause valid proofs to fail verification.
//
// TRACE LAYOUT
// ============
// Col 0: step counter [0, 1, 2, ..., trace_len-1]
// Col 1+: circuit variables (a, b, result, ...) + gt/lt aux columns
//
// For gt/lt gates, auxiliary columns are added:
//   __diff_N:      the difference value (a-b-1 for gt, b-a-1 for lt)
//   __bit_N_0..63: binary decomposition of diff (64 bits)

use crate::types::{Circuit, Gate};

use winterfell::math::{
    ExtensionOf, FieldElement as WinterFieldElement, fields::f128::BaseElement, StarkField,
    ToElements,
};
use winterfell::{
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, EvaluationFrame, FieldExtension,
    ProofOptions, TraceInfo, TransitionConstraintDegree,
};
use std::collections::HashMap;

/// Column 0 is the step counter; circuit variables start at column 1.
pub const CIRCUIT_COL_OFFSET: usize = 1;

/// Public inputs for the Minerva AIR.
#[derive(Clone, Debug)]
pub struct MinervaPublicInputs {
    /// initial_values[0] = 0 (counter), initial_values[1+] = circuit variable values at step 0.
    pub initial_values: Vec<BaseElement>,
    /// Variable names: "__counter" at index 0, then circuit variable names.
    pub variable_names: Vec<String>,
    /// The circuit — needed to reconstruct transition constraints in Air::new.
    pub circuit: Circuit,
}

impl ToElements<BaseElement> for MinervaPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elems = self.initial_values.clone();
        use sha2::{Digest, Sha256};
        let json = serde_json::to_string(&self.circuit).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(json.as_bytes());
        let hash = h.finalize();
        let v = u128::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8],
            hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
        ]);
        elems.push(BaseElement::new(v % BaseElement::MODULUS));
        elems
    }
}

/// Minerva circuit AIR.
pub struct MinervaAir {
    context: AirContext<BaseElement>,
    circuit: Circuit,
    pub_inputs: MinervaPublicInputs,
    /// Maps circuit variable name → Winterfell column index
    variable_map: HashMap<String, usize>,
    num_variables: usize,
}

impl MinervaAir {
    /// Count the number of assertions (used to allocate AirContext).
    fn count_assertions(pub_inputs: &MinervaPublicInputs) -> usize {
        let nonzero = pub_inputs
            .initial_values
            .iter()
            .filter(|&&v| v != BaseElement::ZERO)
            .count();
        // +1 for counter=0 assertion
        (nonzero + 1).max(1)
    }
}

impl Air for MinervaAir {
    type BaseField = BaseElement;
    type PublicInputs = MinervaPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let width = trace_info.width();
        let mut variable_map = HashMap::new();
        for (wf_col, name) in pub_inputs.variable_names.iter().enumerate() {
            if name != "__counter" && !name.starts_with("__pad_") {
                variable_map.insert(name.clone(), wf_col);
            }
        }
        let circuit = pub_inputs.circuit.clone();

        // All transition constraints are degree-1.
        let degrees = vec![TransitionConstraintDegree::new(1); width.max(1)];

        let num_assertions = Self::count_assertions(&pub_inputs);
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        Self {
            context,
            circuit,
            pub_inputs,
            variable_map,
            num_variables: width,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: ExtensionOf<Self::BaseField> + WinterFieldElement>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Column 0: step counter increments by 1
        if !result.is_empty() && !current.is_empty() && !next.is_empty() {
            result[0] = next[0] - current[0] - E::ONE;
        }

        // Circuit columns (1..width)
        for wf_col in CIRCUIT_COL_OFFSET..result.len() {
            if wf_col >= current.len() || wf_col >= next.len() {
                break;
            }

            let col_name = self
                .pub_inputs
                .variable_names
                .get(wf_col)
                .map(|s| s.as_str())
                .unwrap_or("");

            // All aux columns (__diff_*, __bit_*) are frozen
            if col_name.starts_with("__diff_") || col_name.starts_with("__bit_") {
                result[wf_col] = next[wf_col] - current[wf_col];
                continue;
            }

            // Find which gate (if any) has this column as output
            let gate_for_col = self.circuit.gates.iter().find(|g| match g {
                Gate::Add { result: r, .. } | Gate::Multiply { result: r, .. } => r == col_name,
                _ => false,
            });

            match gate_for_col {
                Some(Gate::Add { left, right, .. }) => {
                    let lc = *self
                        .variable_map
                        .get(left)
                        .unwrap_or(&CIRCUIT_COL_OFFSET);
                    let rc = *self
                        .variable_map
                        .get(right)
                        .unwrap_or(&(CIRCUIT_COL_OFFSET + 1));
                    if lc < current.len() && rc < current.len() {
                        result[wf_col] = next[wf_col] - (current[lc] + current[rc]);
                    }
                }
                Some(Gate::Multiply { left, right, .. }) => {
                    let lc = *self
                        .variable_map
                        .get(left)
                        .unwrap_or(&CIRCUIT_COL_OFFSET);
                    let rc = *self
                        .variable_map
                        .get(right)
                        .unwrap_or(&(CIRCUIT_COL_OFFSET + 1));
                    if lc < current.len() && rc < current.len() {
                        result[wf_col] = next[wf_col] - current[lc] * current[rc];
                    }
                }
                _ => {
                    // Frozen: next[i] = current[i]
                    result[wf_col] = next[wf_col] - current[wf_col];
                }
            }
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Counter starts at 0 at step 0
        assertions.push(Assertion::single(0, 0, BaseElement::ZERO));

        // Public input values + diff/bit values at step 0 (all non-zero only)
        for (wf_col, &val) in self.pub_inputs.initial_values.iter().enumerate() {
            if wf_col > 0 && val != BaseElement::ZERO && wf_col < self.num_variables {
                assertions.push(Assertion::single(wf_col, 0, val));
            }
        }

        assertions
    }

    fn get_aux_assertions<E: ExtensionOf<Self::BaseField> + WinterFieldElement>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![]
    }
}

/// Proof options that must match the prover exactly.
pub fn get_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_options() {
        let _options = get_proof_options();
    }

    #[test]
    fn test_to_elements_includes_circuit_hash() {
        let pub_inputs = MinervaPublicInputs {
            initial_values: vec![BaseElement::ZERO, BaseElement::new(42)],
            variable_names: vec!["__counter".to_string(), "x".to_string()],
            circuit: Circuit { gates: vec![] },
        };
        let elems = pub_inputs.to_elements();
        // initial_values (2) + circuit hash (1) = 3
        assert_eq!(elems.len(), 3);
    }
}
