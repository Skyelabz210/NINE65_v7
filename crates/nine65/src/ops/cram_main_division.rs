//! Exact unsigned integer quotient/remainder over encrypted Boolean words.
//!
//! Each bit is an ordinary main-Q BFV ciphertext with an immutable noise bound.
//! Inputs originate at explicit integer ingress; a single scalar ciphertext
//! cannot be reinterpreted as a larger integer without losing its lift.
//! Evaluation has public loop bounds, uses public evaluation keys only, and
//! returns the divide-by-zero predicate encrypted. No divisor inverse is used.

use super::*;

#[path = "integer_division_circuit.rs"]
mod circuit;
use circuit::{Circuit, Node};

#[derive(Debug, thiserror::Error)]
pub enum IntegerDivisionError {
    #[error("integer width must be between 1 and 64 bits")]
    Width,
    #[error("integer input exceeds its declared width")]
    InputRange,
    #[error("integer division preflight at gate {gate}: {reason}")]
    Noise { gate: usize, reason: &'static str },
    #[error("invalid internal integer division circuit: {0}")]
    InternalCircuit(&'static str),
    #[error(transparent)]
    Evaluator(#[from] CramMainError),
}

/// A sealed little-endian word. Only Boolean ingress and admitted Boolean
/// operations can construct its bits; arbitrary scalar ciphertexts cannot.
///
/// ```compile_fail
/// use nine65::ops::cram_main::division::EncryptedUint;
/// let invalid = EncryptedUint { bits: vec![] };
/// ```
#[derive(Clone)]
pub struct EncryptedUint {
    bits: Vec<CramMainCiphertext>,
}

impl EncryptedUint {
    pub fn width(&self) -> usize {
        self.bits.len()
    }
}

pub struct EncryptedDivRem {
    pub quotient: EncryptedUint,
    pub remainder: EncryptedUint,
    pub divide_by_zero: CramMainCiphertext,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnsignedDivRem {
    pub quotient: u64,
    pub remainder: u64,
    pub divide_by_zero: bool,
}

/// Admission depends on public widths and the operands' existing noise
/// histories. It never depends on an encrypted bit or a secret key.
pub struct IntegerDivisionPlan {
    circuit: Circuit,
    multiplications: usize,
    output_budget_millibits: i64,
}

impl IntegerDivisionPlan {
    pub fn gates(&self) -> usize {
        self.circuit.nodes.len()
    }
    pub fn multiplications(&self) -> usize {
        self.multiplications
    }
    pub fn output_budget_millibits(&self) -> i64 {
        self.output_budget_millibits
    }
}

impl CramMainEvaluator {
    pub fn encrypt_uint(
        &self,
        value: u64,
        width: usize,
    ) -> Result<EncryptedUint, IntegerDivisionError> {
        self.encrypt_uint_with_rng(value, width, &mut SecureRng::new())
    }

    pub fn encrypt_uint_with_rng<R: FheRng>(
        &self,
        value: u64,
        width: usize,
        rng: &mut R,
    ) -> Result<EncryptedUint, IntegerDivisionError> {
        if !(1..=64).contains(&width) {
            return Err(IntegerDivisionError::Width);
        }
        if width < 64 && value >= 1u64 << width {
            return Err(IntegerDivisionError::InputRange);
        }
        let bits = (0..width)
            .map(|i| self.encrypt_with_rng((value >> i) & 1, rng))
            .collect::<Result<_, _>>()?;
        Ok(EncryptedUint { bits })
    }

    pub fn plan_integer_division(
        &self,
        numerator: &EncryptedUint,
        denominator: &EncryptedUint,
    ) -> Result<IntegerDivisionPlan, IntegerDivisionError> {
        for bit in numerator.bits.iter().chain(&denominator.bits) {
            self.check(bit)?;
        }
        let circuit = Circuit::new(numerator.width(), denominator.width());
        let model = &self.state.noise;
        let mut bounds: Vec<CertifiedNoiseBound> = Vec::with_capacity(circuit.nodes.len());
        let mut multiplications = 0;
        for (gate, &node) in circuit.nodes.iter().enumerate() {
            let result = (|| -> Result<CertifiedNoiseBound, &'static str> {
                Ok(match node {
                    Node::Constant(value) => {
                        let zero = model.scalar(&numerator.bits[0].bound, 0)?;
                        model.add_plain(&zero, i64::from(value))?
                    }
                    Node::Input(n, i) => (if n {
                        &numerator.bits[i]
                    } else {
                        &denominator.bits[i]
                    })
                    .bound
                    .clone(),
                    Node::Not(a) => model.add_plain(&model.scalar(&bounds[a], -1)?, 1)?,
                    Node::DisjointOr(a, b) => model.add(&bounds[a], &bounds[b])?,
                    Node::And(a, b) => {
                        multiplications += 1;
                        model.multiply(&bounds[a], &bounds[b])?
                    }
                    Node::Xor(a, b) => {
                        multiplications += 1;
                        let product = model.multiply(&bounds[a], &bounds[b])?;
                        model.add(
                            &model.add(&bounds[a], &bounds[b])?,
                            &model.scalar(&product, 2)?,
                        )?
                    }
                    Node::Select(c, a, b) => {
                        multiplications += 1;
                        let difference = model.add(&bounds[a], &bounds[b])?;
                        model.add(&bounds[b], &model.multiply(&bounds[c], &difference)?)?
                    }
                })
            })();
            bounds.push(result.map_err(|reason| IntegerDivisionError::Noise { gate, reason })?);
        }
        let output_budget_millibits = circuit
            .quotient
            .iter()
            .chain(&circuit.remainder)
            .chain(std::iter::once(&circuit.zero))
            .map(|&wire| model.remaining_millibits(&bounds[wire]))
            .min()
            .ok_or(IntegerDivisionError::InternalCircuit(
                "missing output bounds",
            ))?;
        Ok(IntegerDivisionPlan {
            circuit,
            multiplications,
            output_budget_millibits,
        })
    }

    /// For d>0, return n=q*d+r with 0<=r<d. For d=0, return (0,n,1).
    /// The predicate is encrypted: the evaluator never learns which case ran.
    /// Output words have the numerator's width. All gates are admitted before
    /// evaluation; finite leveled-noise limits are not bypassed or reset.
    pub fn divide_integer(
        &self,
        numerator: &EncryptedUint,
        denominator: &EncryptedUint,
    ) -> Result<EncryptedDivRem, IntegerDivisionError> {
        let plan = self.plan_integer_division(numerator, denominator)?;
        let circuit = plan.circuit;
        let mut uses = vec![0usize; circuit.nodes.len()];
        for node in &circuit.nodes {
            for input in node.inputs() {
                uses[input] += 1;
            }
        }
        for &wire in circuit
            .quotient
            .iter()
            .chain(&circuit.remainder)
            .chain(std::iter::once(&circuit.zero))
        {
            uses[wire] += 1;
        }
        let mut values: Vec<Option<CramMainCiphertext>> = vec![None; circuit.nodes.len()];
        for (gate, &node) in circuit.nodes.iter().enumerate() {
            let value = |i: usize| live_value(&values, i);
            let result = match node {
                Node::Constant(v) => {
                    self.add_plain(&self.mul_plain(&numerator.bits[0], 0)?, u64::from(v))?
                }
                Node::Input(n, i) => (if n {
                    &numerator.bits[i]
                } else {
                    &denominator.bits[i]
                })
                .clone(),
                Node::Not(a) => self.add_plain(&self.negate(value(a)?)?, 1)?,
                Node::DisjointOr(a, b) => self.add(value(a)?, value(b)?)?,
                Node::And(a, b) => self.multiply(value(a)?, value(b)?)?,
                Node::Xor(a, b) => {
                    let product = self.multiply(value(a)?, value(b)?)?;
                    self.sub(
                        &self.add(value(a)?, value(b)?)?,
                        &self.scale_signed(&product, 2)?,
                    )?
                }
                Node::Select(c, a, b) => {
                    let difference = self.sub(value(a)?, value(b)?)?;
                    self.add(value(b)?, &self.multiply(value(c)?, &difference)?)?
                }
            };
            values[gate] = Some(result);
            for input in node.inputs() {
                uses[input] -= 1;
                if uses[input] == 0 {
                    values[input] = None;
                }
            }
        }
        let word = |wires: &[usize]| -> Result<EncryptedUint, IntegerDivisionError> {
            Ok(EncryptedUint {
                bits: wires
                    .iter()
                    .map(|&w| live_value(&values, w).cloned())
                    .collect::<Result<_, _>>()?,
            })
        };
        Ok(EncryptedDivRem {
            quotient: word(&circuit.quotient)?,
            remainder: word(&circuit.remainder)?,
            divide_by_zero: live_value(&values, circuit.zero)?.clone(),
        })
    }
}

fn live_value(
    values: &[Option<CramMainCiphertext>],
    wire: usize,
) -> Result<&CramMainCiphertext, IntegerDivisionError> {
    values
        .get(wire)
        .and_then(Option::as_ref)
        .ok_or(IntegerDivisionError::InternalCircuit("missing live wire"))
}

impl CramMainClient {
    pub fn decrypt_uint(&self, word: &EncryptedUint) -> Result<u64, CramMainError> {
        let mut value = 0u64;
        for (i, bit) in word.bits.iter().enumerate() {
            let decoded = self.decrypt(bit)?;
            if decoded > 1 {
                return Err(CramMainError::Decode);
            }
            value |= decoded << i;
        }
        Ok(value)
    }

    pub fn decrypt_division(
        &self,
        result: &EncryptedDivRem,
    ) -> Result<UnsignedDivRem, CramMainError> {
        let status = self.decrypt(&result.divide_by_zero)?;
        if status > 1 {
            return Err(CramMainError::Decode);
        }
        Ok(UnsignedDivRem {
            quotient: self.decrypt_uint(&result.quotient)?,
            remainder: self.decrypt_uint(&result.remainder)?,
            divide_by_zero: status == 1,
        })
    }
}

#[cfg(test)]
#[path = "cram_main_division_tests.rs"]
mod tests;
