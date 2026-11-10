//! Explicit, bounded scheduling for the unadmitted public research circuit.
//!
//! Forecasts use producer-issued bounds and the existing integer noise ledger.
//! Every successful add, multiply or square leaves its output inside the
//! circuit's source support. This is conservative admission, not an
//! observed-error measurement.
//! There is no fallback to legacy bootstrap, secret-key refresh, or metadata
//! reset. The scheduler owns only the public circuit; the client keeps secrets.

use super::{PublicRefreshCircuit, PublicRefreshCircuitCertificate, SourceWorkCiphertext};
use crate::arithmetic::rns::U512;
use crate::entropy::FheRng;
use crate::errors::Nine65Error;
use crate::ops::public_refresh_source::SourceError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduledOperation {
    Add,
    Multiply,
    Square,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOperands {
    Neither,
    Left,
    Right,
    Both,
}

impl RefreshOperands {
    pub fn count(self) -> u64 {
        match self {
            Self::Neither => 0,
            Self::Left | Self::Right => 1,
            Self::Both => 2,
        }
    }

    fn left(self) -> bool {
        matches!(self, Self::Left | Self::Both)
    }

    fn right(self) -> bool {
        matches!(self, Self::Right | Self::Both)
    }
}

/// Advisory snapshot, not authority to execute or change a ciphertext bound.
/// Execution always recomputes admission from the supplied sealed inputs.
#[derive(Clone, Debug)]
pub struct OperationForecast {
    pub operation: ScheduledOperation,
    pub family_id: [u8; 32],
    pub input_lineages: [[u8; 32]; 2],
    pub refresh_operands: RefreshOperands,
    pub output_scaled_error_bound: U512,
    pub output_source_radius: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("source admission failed: {0}")]
    Source(#[from] SourceError),
    #[error("no supported public-refresh schedule funds {operation:?}")]
    OperationUnfunded { operation: ScheduledOperation },
    #[error("public refresh needs {required} attempts, but only {remaining} remain")]
    RefreshBudgetExceeded { required: u64, remaining: u64 },
    #[error("public refresh of {operand:?} failed: {source}")]
    RefreshFailed {
        operand: RefreshOperands,
        #[source]
        source: Nine65Error,
    },
    #[error("encrypted public-refresh output disagrees with its forecast")]
    ForecastMismatch,
}

/// Opt-in public research scheduler. `max_refresh_attempts` is a lifetime cap
/// for this wrapper, including failed attempts. A square refreshes one input
/// once; a binary operation can refresh at most two inputs. No retry is hidden.
/// This does not establish production security or a native throughput claim.
pub struct PublicResearchRefreshScheduler {
    circuit: PublicRefreshCircuit,
    max_refresh_attempts: u64,
    refresh_attempts: u64,
}

impl PublicResearchRefreshScheduler {
    pub fn new(circuit: PublicRefreshCircuit, max_refresh_attempts: u64) -> Self {
        Self {
            circuit,
            max_refresh_attempts,
            refresh_attempts: 0,
        }
    }

    pub fn certificate(&self) -> &PublicRefreshCircuitCertificate {
        self.circuit.certificate()
    }

    /// Includes successful circuit refreshes performed before wrapping it.
    pub fn real_refreshes(&self) -> u64 {
        self.circuit.real_refreshes()
    }

    pub fn refresh_attempts(&self) -> u64 {
        self.refresh_attempts
    }

    pub fn remaining_refresh_attempts(&self) -> u64 {
        self.max_refresh_attempts - self.refresh_attempts
    }

    pub fn encrypt(&self, coefficients: &[u64]) -> Result<SourceWorkCiphertext, SchedulerError> {
        Ok(self.circuit.source.encrypt(coefficients)?)
    }

    pub fn encrypt_with_rng<R: FheRng>(
        &self,
        coefficients: &[u64],
        rng: &mut R,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        Ok(self.circuit.source.encrypt_with_rng(coefficients, rng)?)
    }

    pub fn forecast_add(
        &self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<OperationForecast, SchedulerError> {
        self.forecast(ScheduledOperation::Add, left, right)
    }

    pub fn forecast_multiply(
        &self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<OperationForecast, SchedulerError> {
        self.forecast(ScheduledOperation::Multiply, left, right)
    }

    pub fn forecast_square(
        &self,
        input: &SourceWorkCiphertext,
    ) -> Result<OperationForecast, SchedulerError> {
        self.forecast(ScheduledOperation::Square, input, input)
    }

    pub fn add(
        &mut self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        self.execute(ScheduledOperation::Add, left, right)
    }

    pub fn multiply(
        &mut self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        self.execute(ScheduledOperation::Multiply, left, right)
    }

    pub fn square(
        &mut self,
        input: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        self.execute(ScheduledOperation::Square, input, input)
    }

    fn forecast(
        &self,
        operation: ScheduledOperation,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<OperationForecast, SchedulerError> {
        // Pointer-identity family admission precedes all numeric forecasts.
        // Matching config, plaintext root, or a caller's old forecast is not
        // sufficient to authorize a foreign ciphertext or a new history.
        let source = &self.circuit.source;
        source.check(left)?;
        source.check(right)?;
        let candidates: &[RefreshOperands] = if operation == ScheduledOperation::Square {
            &[RefreshOperands::Neither, RefreshOperands::Left]
        } else {
            &[
                RefreshOperands::Neither,
                RefreshOperands::Left,
                RefreshOperands::Right,
                RefreshOperands::Both,
            ]
        };
        for &refresh in candidates {
            if refresh.left() && !self.can_refresh(left)? {
                continue;
            }
            if refresh.right() && !self.can_refresh(right)? {
                continue;
            }
            let returned = self.certificate().returned_scaled_error_bound;
            let a = if refresh.left() {
                returned
            } else {
                left.scaled_error_bound()
            };
            let b =
                if refresh.right() || (operation == ScheduledOperation::Square && refresh.left()) {
                    returned
                } else {
                    right.scaled_error_bound()
                };
            let plan = source.plan();
            let result = match operation {
                ScheduledOperation::Add => plan.forecast_add_bounds(a, b),
                ScheduledOperation::Multiply | ScheduledOperation::Square => {
                    plan.forecast_multiply_bounds(a, b)
                }
            };
            let Some(bound) = capacity(result)? else {
                continue;
            };
            let Some(radius) = capacity(plan.forecast_source_radius(bound))? else {
                continue;
            };
            if radius > self.certificate().carry_radius as u64 {
                continue;
            }
            let required = refresh.count();
            let remaining = self.remaining_refresh_attempts();
            if required > remaining {
                return Err(SchedulerError::RefreshBudgetExceeded {
                    required,
                    remaining,
                });
            }
            return Ok(OperationForecast {
                operation,
                family_id: *source.family_id(),
                input_lineages: [*left.lineage(), *right.lineage()],
                refresh_operands: refresh,
                output_scaled_error_bound: bound,
                output_source_radius: radius,
            });
        }
        Err(SchedulerError::OperationUnfunded { operation })
    }

    fn can_refresh(&self, input: &SourceWorkCiphertext) -> Result<bool, SchedulerError> {
        Ok(
            capacity(self.circuit.source.forecast_refresh_radius(input))?
                .is_some_and(|radius| radius <= self.certificate().carry_radius as u64),
        )
    }

    fn refresh(
        &mut self,
        input: &SourceWorkCiphertext,
        operand: RefreshOperands,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        // The whole operation was budgeted before doing any encrypted work.
        // Count attempts before invoking a potentially failing backend.
        self.refresh_attempts += 1;
        let output = self
            .circuit
            .refresh(input)
            .map_err(|source| SchedulerError::RefreshFailed { operand, source })?;
        if output.scaled_error_bound() != self.certificate().returned_scaled_error_bound
            || !std::ptr::eq(output.root(), input.root())
            || output.lineage() == input.lineage()
        {
            return Err(SchedulerError::ForecastMismatch);
        }
        Ok(output)
    }

    fn execute(
        &mut self,
        operation: ScheduledOperation,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SchedulerError> {
        let forecast = self.forecast(operation, left, right)?;
        let refreshed_left = if forecast.refresh_operands.left() {
            Some(self.refresh(left, RefreshOperands::Left)?)
        } else {
            None
        };
        let refreshed_right = if forecast.refresh_operands.right() {
            Some(self.refresh(right, RefreshOperands::Right)?)
        } else {
            None
        };
        let a = refreshed_left.as_ref().unwrap_or(left);
        let b = if operation == ScheduledOperation::Square {
            a
        } else {
            refreshed_right.as_ref().unwrap_or(right)
        };
        let output = match operation {
            ScheduledOperation::Add => self.circuit.source.add(a, b)?,
            ScheduledOperation::Multiply | ScheduledOperation::Square => {
                self.circuit.source.multiply(a, b)?
            }
        };
        if output.scaled_error_bound() != forecast.output_scaled_error_bound {
            return Err(SchedulerError::ForecastMismatch);
        }
        Ok(output)
    }
}

// Only expected capacity refusal means try another public schedule. All other
// failures retain their typed cause; no unexpected backend error is swallowed.
fn capacity<T>(result: Result<T, SourceError>) -> Result<Option<T>, SchedulerError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(SourceError::NoiseExhausted) => Ok(None),
        Err(error) => Err(SchedulerError::Source(error)),
    }
}

#[cfg(test)]
#[path = "public_refresh_scheduler_tests.rs"]
mod tests;
