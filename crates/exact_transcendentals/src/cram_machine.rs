//! CRAM — Configurable Residue Arithmetic Machine.
//!
//! `cram_ops` supplies the algebra: eight operators and a [`Schema`] that
//! assigns a *different* operator to each lane. This module supplies the
//! machine that runs it.
//!
//! # Residue space is the native math space
//!
//! The registers hold residue tuples. Not a decomposition of some "real"
//! integer kept elsewhere — the tuple **is** the number. Execution never
//! reconstructs, because there is nothing to reconstruct *to*: projecting to
//! an integer is leaving the space, not arriving at the answer.
//!
//! That is enforced, not asserted. [`Cram::projections`] counts every exit,
//! and [`Cram::exec`] cannot increment it — only [`Cram::project`] can. A
//! program that ran natively can prove it did.
//!
//! # Heterogeneous lanes
//!
//! The defining move: lanes are not interchangeable. Each carries a role and
//! may run a different operator in the same instruction. `AMSI` applies Add to
//! the ground lane, Mul to surface, Sub to bridge, Inv to shadow. No positional
//! system can express that, because a carry would couple the digits. Residue
//! lanes are independent, so the operators can differ.
//!
//! # DKAM gate
//!
//! Every schema is checked at load: `max_deg(schema) < rho(basis)`, where rho
//! is the smallest modulus. All eight operators are degree <= 2, so any basis
//! whose smallest prime is >= 3 admits every schema. The gate is enforced
//! before execution rather than assumed — a basis containing 2 fails it, which
//! is why the discriminating basis is {3,5,7,11,13}.

use crate::cram_ops::{parse_schema, CramOp, CramOpError, Schema};

/// Architectural role of a lane. Roles are not interchangeable: replacing a
/// prime with a same-size prime carrying different residue structure changes
/// what the lane witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneRole {
    /// 3 — fabric / triadic; sets the resonance order of the basis.
    Ground,
    /// 5 — surface / first Ramanujan modulus; measurement lane.
    Surface,
    /// 7 — bridge; links the low basis to the shadow (the (7,11) cousin pair).
    Bridge,
    /// 11 — shadow anchor; the disambiguator.
    Shadow,
    /// 13 — boundary; first prime with nonzero cusp-form dimension.
    Boundary,
    /// Any lane outside the canonical five.
    Extension(u64),
}

impl LaneRole {
    /// Canonical role for a modulus in the discriminating basis.
    pub fn of(p: u64) -> Self {
        match p {
            3 => LaneRole::Ground,
            5 => LaneRole::Surface,
            7 => LaneRole::Bridge,
            11 => LaneRole::Shadow,
            13 => LaneRole::Boundary,
            other => LaneRole::Extension(other),
        }
    }
}

/// The canonical CRAM schema basis. 2 is absent because it would drop rho to 2
/// and fail the DKAM gate for every degree-2 operator.
///
/// That criterion is **this register's alone**. The Transport Core
/// (`cram_pde::TRANSPORT_CORE`) also omits 2, but on entirely different
/// grounds: it is `{p in S6 : gcd(p, SCALE) = 1}` with `SCALE = 10^4 = 2^4·5^4`,
/// which excludes 2 and 5 identically, as parking lanes of the decimal scale.
/// Both registers happen to land on rho = 3, which is exactly why the two
/// rationales are easy to conflate — so the gate
/// `tests/cram_gates.rs::p8_basis_registers_are_distinct_and_derived_not_asserted`
/// derives the Transport Core from its definition rather than asserting its
/// listed value.
pub const DISCRIMINATING_BASIS: [u64; 5] = [3, 5, 7, 11, 13];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CramError {
    /// Register index out of range.
    BadRegister { index: usize, count: usize },
    /// Underlying operator failure (non-invertible operand, bad notation, ...).
    Op(CramOpError),
    /// `step` was called on a machine with no configured schema.
    NotConfigured,
    /// The register's lanes no longer come from one integer operation, so no
    /// winding names them and there is no integer to project to. Carries why.
    NoWinding(WindingLoss),
    /// The winding arithmetic would exceed `i128`. Refused, never wrapped.
    WindingOverflow,
    /// `g = (a + K) mod A` landed on `M`, the one residue no canonical value can
    /// take. The anchor lane and the winding disagree: the state is corrupt.
    InconsistentState { g: i128, m: i128 },
}

impl From<CramOpError> for CramError {
    fn from(e: CramOpError) -> Self {
        CramError::Op(e)
    }
}

// ─── The Adelic State Tuple ───────────────────────────────────────────────

/// Why a register stopped naming an integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindingLoss {
    /// The schema assigned different operators to different lanes. That is the
    /// defining CRAM move and it is not an integer operation: there is no
    /// single function of the two inputs whose reduction gives these lanes, so
    /// no winding names the result. The residues remain perfectly valid.
    Heterogeneous { notation: String },
    /// Every lane ran the same operator, but that operator is modular-only.
    /// `Div` and `Inv` produce `a·b⁻¹ mod p`, which is **not** `⌊a/b⌋` — the
    /// chimera-1 trap. Lifting one to an integer would invent an answer.
    ModularOnly { op: char },
}

/// `X = g + K·M`, where `g` is the canonical representative in `[0, M)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Winding {
    /// The register names the integer `g + K·M`.
    Known(i128),
    /// It names a residue tuple and nothing more.
    Undefined(WindingLoss),
}

impl Winding {
    pub fn known(&self) -> Option<i128> {
        match self {
            Winding::Known(k) => Some(*k),
            Winding::Undefined(_) => None,
        }
    }
}

/// Sign of the integer named, read from the winding alone.
///
/// `X = g + K·M` with `g ≥ 0` and `M > 0`, so `X < 0` exactly when `K < 0`.
/// No lane is consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign {
    Negative,
    NonNegative,
    /// No winding, so no sign — a residue tuple has no order.
    Unavailable,
}

/// Parity, read from the 2-lane when the basis has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    Even,
    Odd,
    /// The basis omits 2, so parity is not a single-lane read and Σ declines to
    /// report it rather than reconstructing across lanes to get it.
    Unavailable,
}

/// Shadow status, read from the 11-lane when the basis has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowStatus {
    /// The shadow anchor lane is zero — the value is on the shadow.
    OnShadow,
    OffShadow,
    Unavailable,
}

/// The Property Signature Σ.
///
/// Every field is derived from **one** source, named in its own documentation:
/// `sign` and `bounds` from the winding, `parity` from the 2-lane, `shadow`
/// from the 11-lane. No field reads two lanes, which is what makes the update
/// `O(1)` with no cross-lane communication — and what
/// `cram_gates::p5_*` can test by perturbing one lane and asserting only that
/// lane's field moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub sign: Sign,
    pub parity: Parity,
    pub shadow: ShadowStatus,
    /// `[K·M, K·M + M)` — the sheet of the CRT torus the value sits on. `None`
    /// when there is no winding to read it from.
    pub bounds: Option<(i128, i128)>,
}

/// The domain the state is being read in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// The integer line. The winding is live and growth is recorded.
    Integers,
    /// The corridor `ℤ_M`. The winding is pinned to 0 and anything that would
    /// wind is a wrap, not a carry — so magnitude is deliberately not tracked.
    Corridor,
}

/// The Adelic State Tuple `S = (r, K, Σ, T)`, plus the anchor lane that makes
/// the winding readable without leaving residue space.
///
/// # The anchor lane
///
/// `A = M + 1` is coprime to every basis prime (it is adjacent to their
/// product), and `M ≡ −1 (mod A)`, so
///
/// ```text
/// X ≡ g + K·M ≡ g − K  (mod A)   ⟹   a = (g − K) mod A
/// ```
///
/// and running it backwards recovers the canonical representative:
///
/// ```text
/// g = (a + K) mod A
/// ```
///
/// This is exact because `g ∈ [0, M)` and `M < A`, so the reduction mod `A` is
/// injective on the range `g` can occupy. It costs one addition and one
/// reduction — **no CRT reconstruction, no Garner**. The single value `g = M`
/// is unreachable, which makes it a free consistency check: seeing it means the
/// anchor lane and the winding disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adelic {
    /// `r` — residues over the machine's basis.
    pub r: Vec<u64>,
    /// The anchor lane, `X mod A` with `A = M + 1`.
    pub a: i128,
    /// `K` — the winding.
    pub k: Winding,
    /// `Σ` — the Property Signature.
    pub sigma: Signature,
    /// `T` — topology / domain context.
    pub topology: Topology,
}

/// Recover the canonical representative `g ∈ [0, M)` from an anchor lane and a
/// winding, in `O(1)` and with no CRT reconstruction.
///
/// ```text
/// A = M + 1,   M ≡ −1 (mod A),   a = (g − K) mod A   ⟹   g = (a + K) mod A
/// ```
///
/// Exact because `g < M < A`, so the reduction is injective on the range `g`
/// can occupy. `g = M` is therefore unreachable: seeing it means the anchor lane
/// and the winding disagree, and it is reported as
/// [`CramError::InconsistentState`] rather than returned.
pub fn canonical_from(a: i128, k: i128, m: i128) -> Result<i128, CramError> {
    let anchor = m.checked_add(1).ok_or(CramError::WindingOverflow)?;
    let g = a
        .checked_add(k)
        .ok_or(CramError::WindingOverflow)?
        .rem_euclid(anchor);
    if g >= m {
        return Err(CramError::InconsistentState { g, m });
    }
    Ok(g)
}

/// One instruction. Registers are addressed by index; every operand and the
/// destination are residue tuples over the machine's basis.
#[derive(Debug, Clone)]
pub enum Instr {
    /// Feed a value straight in, projected onto the basis.
    Load { dst: usize, value: i128 },
    /// Apply a heterogeneous schema: `dst = schema(a, b)`, lane by lane.
    Apply {
        dst: usize,
        a: usize,
        b: usize,
        schema: String,
    },
}

/// A Configurable Residue Arithmetic Machine.
pub struct Cram {
    basis: Vec<u64>,
    roles: Vec<LaneRole>,
    /// `M` — the basis product, the corridor width.
    m: i128,
    /// `A = M + 1` — the adjacent anchor lane's modulus.
    anchor: i128,
    /// Lane index of 2, if the basis has one. Σ's only parity source.
    parity_lane: Option<usize>,
    /// Lane index of 11, if the basis has one. Σ's only shadow source.
    shadow_lane: Option<usize>,
    regs: Vec<Adelic>,
    config: Option<Schema>,
    projections: usize,
    destructive_reads: usize,
    ops_executed: usize,
}

impl Cram {
    /// Build a machine over `basis` with `n_regs` registers, all zeroed.
    ///
    /// # Panics
    ///
    /// If the basis product `M` or its anchor `M + 1` exceeds `i128`. A machine
    /// whose corridor cannot be represented would silently mis-report every
    /// winding, so this is refused loudly rather than saturated. Use
    /// [`Cram::try_new`] to handle it as a value.
    pub fn new(basis: &[u64], n_regs: usize) -> Self {
        Self::try_new(basis, n_regs).expect("basis product must fit i128 with room for its anchor")
    }

    /// Fallible constructor. `None` if `M + 1` does not fit `i128`.
    pub fn try_new(basis: &[u64], n_regs: usize) -> Option<Self> {
        let roles = basis.iter().map(|&p| LaneRole::of(p)).collect();
        let mut m: i128 = 1;
        for &p in basis {
            m = m.checked_mul(p as i128)?;
        }
        let anchor = m.checked_add(1)?;
        let parity_lane = basis.iter().position(|&p| p == 2);
        let shadow_lane = basis.iter().position(|&p| p == 11);
        let zero = Adelic {
            r: vec![0u64; basis.len()],
            a: 0,
            k: Winding::Known(0),
            sigma: Signature {
                sign: Sign::NonNegative,
                parity: match parity_lane {
                    Some(_) => Parity::Even,
                    None => Parity::Unavailable,
                },
                shadow: match shadow_lane {
                    Some(_) => ShadowStatus::OnShadow,
                    None => ShadowStatus::Unavailable,
                },
                bounds: Some((0, m)),
            },
            topology: Topology::Integers,
        };
        Some(Cram {
            basis: basis.to_vec(),
            roles,
            m,
            anchor,
            parity_lane,
            shadow_lane,
            regs: vec![zero; n_regs],
            config: None,
            projections: 0,
            destructive_reads: 0,
            ops_executed: 0,
        })
    }

    /// `M`, the basis product.
    pub fn modulus(&self) -> i128 {
        self.m
    }

    /// `A = M + 1`, the adjacent anchor lane's modulus.
    pub fn anchor(&self) -> i128 {
        self.anchor
    }

    /// The whole Adelic tuple for a register.
    pub fn state(&self, reg: usize) -> Result<&Adelic, CramError> {
        self.check_reg(reg)?;
        Ok(&self.regs[reg])
    }

    /// The Property Signature Σ of a register.
    pub fn signature(&self, reg: usize) -> Result<Signature, CramError> {
        Ok(self.state(reg)?.sigma)
    }

    /// The winding `K` of a register.
    pub fn winding(&self, reg: usize) -> Result<&Winding, CramError> {
        Ok(&self.state(reg)?.k)
    }

    /// Rebuild Σ from the tuple. Each field reads exactly one source.
    fn signature_of(&self, r: &[u64], k: &Winding) -> Signature {
        let (sign, bounds) = match k {
            // Winding only. No lane is consulted.
            Winding::Known(kk) => (
                if *kk < 0 {
                    Sign::Negative
                } else {
                    Sign::NonNegative
                },
                Some((kk * self.m, kk * self.m + self.m)),
            ),
            Winding::Undefined(_) => (Sign::Unavailable, None),
        };
        Signature {
            sign,
            // The 2-lane only.
            parity: match self.parity_lane {
                Some(i) if r[i] == 0 => Parity::Even,
                Some(_) => Parity::Odd,
                None => Parity::Unavailable,
            },
            // The 11-lane only.
            shadow: match self.shadow_lane {
                Some(i) if r[i] == 0 => ShadowStatus::OnShadow,
                Some(_) => ShadowStatus::OffShadow,
                None => ShadowStatus::Unavailable,
            },
            bounds,
        }
    }

    /// The canonical representative `g = X mod M`, recovered from the anchor
    /// lane and the winding in `O(1)`.
    ///
    /// `g = (a + K) mod A`. This is the whole reason the anchor lane is carried:
    /// it makes the canonical value readable **without CRT reconstruction**.
    fn canonical(&self, s: &Adelic) -> Result<i128, CramError> {
        let k = match &s.k {
            Winding::Known(k) => *k,
            Winding::Undefined(loss) => return Err(CramError::NoWinding(loss.clone())),
        };
        canonical_from(s.a, k, self.m)
    }

    /// Machine over [`DISCRIMINATING_BASIS`].
    pub fn discriminating(n_regs: usize) -> Self {
        Self::new(&DISCRIMINATING_BASIS, n_regs)
    }

    pub fn basis(&self) -> &[u64] {
        &self.basis
    }

    pub fn roles(&self) -> &[LaneRole] {
        &self.roles
    }

    /// Resonance order: the smallest modulus. The DKAM clean window is the
    /// set of degrees strictly below it.
    pub fn rho(&self) -> u64 {
        self.basis.iter().copied().min().unwrap_or(0)
    }

    /// Number of times execution left residue space. Stays 0 for any program
    /// that never calls [`Self::project`].
    pub fn projections(&self) -> usize {
        self.projections
    }

    pub fn ops_executed(&self) -> usize {
        self.ops_executed
    }

    /// Parse a schema against this machine's basis.
    ///
    /// The DKAM gate lives in `cram_ops::parse_schema`, which rejects any
    /// schema whose maximum operator degree is not strictly below the basis
    /// resonance order (`CramOpError::DegreeViolation`). This method does not
    /// re-check it: a second gate here would be unreachable, and an
    /// unreachable guard reads as protection that is not there.
    pub fn schema(&self, notation: &str) -> Result<Schema, CramError> {
        Ok(parse_schema(notation, &self.basis)?)
    }

    fn check_reg(&self, i: usize) -> Result<(), CramError> {
        if i >= self.regs.len() {
            return Err(CramError::BadRegister {
                index: i,
                count: self.regs.len(),
            });
        }
        Ok(())
    }

    /// Feed a value in. This is an entry, not an exit — it does not touch the
    /// projection counter.
    ///
    /// The whole tuple is laid down at once: residues, anchor lane, winding and
    /// Σ. Nothing here is recomputed later.
    pub fn load(&mut self, dst: usize, value: i128) -> Result<(), CramError> {
        self.check_reg(dst)?;
        let topology = self.regs[dst].topology;
        let (k, value) = match topology {
            Topology::Integers => (value.div_euclid(self.m), value),
            // In the corridor the winding is pinned: the value wraps.
            Topology::Corridor => (0, value.rem_euclid(self.m)),
        };
        let r: Vec<u64> = self
            .basis
            .iter()
            .map(|&p| value.rem_euclid(p as i128) as u64)
            .collect();
        let a = value.rem_euclid(self.anchor);
        let k = Winding::Known(k);
        let sigma = self.signature_of(&r, &k);
        self.regs[dst] = Adelic {
            r,
            a,
            k,
            sigma,
            topology,
        };
        Ok(())
    }

    /// Put a register in a topology. Reloading is required afterwards; the
    /// topology is context for what the winding *means*, not a conversion.
    pub fn set_topology(&mut self, reg: usize, t: Topology) -> Result<(), CramError> {
        self.check_reg(reg)?;
        self.regs[reg].topology = t;
        Ok(())
    }

    /// Read the register in its native form. No reconstruction, no counter.
    pub fn read(&self, reg: usize) -> Result<&[u64], CramError> {
        self.check_reg(reg)?;
        Ok(&self.regs[reg].r)
    }

    /// **An exit.** Projects to the canonical representative in `[0, M)` and
    /// records that residue space was left.
    ///
    /// Two reads are possible and the machine records which one it had to use:
    ///
    /// - **Anchored** (`g = (a + K) mod A`) when the register still has a
    ///   winding. `O(1)`, no CRT reconstruction, and the residues are untouched.
    /// - **Destructive** (Garner) when it does not. A heterogeneous schema
    ///   leaves lanes that no single integer operation produced, so the anchor
    ///   lane no longer tracks them; the only way out is to consume the
    ///   residues into one accumulator. That is counted separately by
    ///   [`Self::destructive_reads`] — it is not free, and pretending otherwise
    ///   is how the distinction gets lost.
    ///
    /// Both count as exits. The cost of leaving is not the point; leaving is.
    pub fn project(&mut self, reg: usize) -> Result<i128, CramError> {
        self.check_reg(reg)?;
        self.projections += 1;
        let s = self.regs[reg].clone();
        match s.k {
            Winding::Known(_) => self.canonical(&s),
            Winding::Undefined(_) => {
                self.destructive_reads += 1;
                let residues: Vec<(i128, i128)> =
                    s.r.iter()
                        .zip(self.basis.iter())
                        .map(|(&r, &p)| (r as i128, p as i128))
                        .collect();
                Ok(crate::k_elim::garner_reconstruct(&residues).unwrap_or(0))
            }
        }
    }

    /// How many exits had to be taken destructively, through Garner, because no
    /// winding was left to take the anchored read with.
    pub fn destructive_reads(&self) -> usize {
        self.destructive_reads
    }

    /// **An exit.** Projects to the full integer `g + K·M`.
    ///
    /// Fails with [`CramError::NoWinding`] when the register no longer names an
    /// integer — after a heterogeneous schema, or after a modular-only operator.
    /// That refusal is the point: inventing a quotient for `a·b⁻¹ mod p` is the
    /// chimera-1 trap.
    pub fn project_integer(&mut self, reg: usize) -> Result<i128, CramError> {
        self.check_reg(reg)?;
        self.projections += 1;
        let s = self.regs[reg].clone();
        let g = self.canonical(&s)?;
        let k = s.k.known().ok_or(CramError::WindingOverflow)?;
        k.checked_mul(self.m)
            .and_then(|t| t.checked_add(g))
            .ok_or(CramError::WindingOverflow)
    }

    /// The winding of `schema(x, y)`, when there is one.
    ///
    /// A winding exists only when the schema names a single integer operation:
    /// every lane running the **same** operator, and that operator being
    /// integer-meaningful. `Div` and `Inv` are excluded even when homogeneous —
    /// they compute `a·b⁻¹ mod p`, which is not `⌊a/b⌋`.
    ///
    /// The arithmetic is §2.1, evaluated on the canonical parts recovered from
    /// the anchor lanes rather than reconstructed:
    ///
    /// ```text
    /// Add:  K = K_x + K_y + [g_x + g_y ≥ M]
    /// Mul:  K = ⌊g_x·g_y / M⌋ + g_x·K_y + g_y·K_x + K_x·K_y·M
    /// ```
    fn propagate(&self, s: &Schema, x: &Adelic, y: &Adelic) -> Result<(Winding, i128), CramError> {
        let ops = s.ops();
        let uniform = ops
            .first()
            .copied()
            .filter(|first| ops.iter().all(|o| o == first));
        let op = match uniform {
            Some(op) => op,
            None => {
                return Ok((
                    Winding::Undefined(WindingLoss::Heterogeneous {
                        notation: s.notation(),
                    }),
                    0,
                ))
            }
        };
        if matches!(op, CramOp::Div | CramOp::Inv) {
            return Ok((
                Winding::Undefined(WindingLoss::ModularOnly { op: op.code() }),
                0,
            ));
        }

        // Unary operators never consult `y`, so a destination fed from a
        // register that has lost its winding is not contaminated by an operand
        // the operator does not read.
        // The winding is checked before the canonical part is asked for: an
        // operand that has already lost its winding propagates that loss, it
        // does not raise an error.
        let binary = op.is_binary();
        let kx = match &x.k {
            Winding::Known(k) => *k,
            Winding::Undefined(l) => return Ok((Winding::Undefined(l.clone()), 0)),
        };
        let gx = self.canonical(x)?;
        let (gy, ky) = if binary {
            let ky = match &y.k {
                Winding::Known(k) => *k,
                Winding::Undefined(l) => return Ok((Winding::Undefined(l.clone()), 0)),
            };
            (self.canonical(y)?, ky)
        } else {
            (gx, kx)
        };

        let ov = || CramError::WindingOverflow;
        let (m, a_mod) = (self.m, self.anchor);

        // §2.1, in split form: the canonical parts and the windings are kept
        // apart, so nothing forms the full integer `g + K·M` and overflows on a
        // magnitude the result could have carried perfectly well.
        let (g_out, k_out) = match op {
            CramOp::Add => {
                let s = gx.checked_add(gy).ok_or_else(ov)?;
                let c = i128::from(s >= m);
                let k = kx
                    .checked_add(ky)
                    .and_then(|t| t.checked_add(c))
                    .ok_or_else(ov)?;
                (s - c * m, k)
            }
            CramOp::Sub => {
                let d = gx - gy; // both in [0, M): no overflow possible
                let borrow = i128::from(d < 0);
                let k = kx
                    .checked_sub(ky)
                    .and_then(|t| t.checked_sub(borrow))
                    .ok_or_else(ov)?;
                (d + borrow * m, k)
            }
            // Sqr is Mul with the operand doubled up; the formula is the same.
            CramOp::Mul | CramOp::Sqr => {
                let prod = gx.checked_mul(gy).ok_or_else(ov)?;
                let t1 = gx.checked_mul(ky).ok_or_else(ov)?;
                let t2 = gy.checked_mul(kx).ok_or_else(ov)?;
                let t3 = kx
                    .checked_mul(ky)
                    .and_then(|p| p.checked_mul(m))
                    .ok_or_else(ov)?;
                let k = (prod / m)
                    .checked_add(t1)
                    .and_then(|t| t.checked_add(t2))
                    .and_then(|t| t.checked_add(t3))
                    .ok_or_else(ov)?;
                (prod % m, k)
            }
            CramOp::Neg => {
                let nonzero = i128::from(gx != 0);
                let k = kx
                    .checked_neg()
                    .and_then(|t| t.checked_sub(nonzero))
                    .ok_or_else(ov)?;
                ((m - gx) % m, k)
            }
            CramOp::Id => (gx, kx),
            CramOp::Div | CramOp::Inv => unreachable!("filtered above"),
        };

        match x.topology {
            Topology::Integers => {
                // The anchor lane is propagated **lane-wise**, from the operand
                // anchor lanes only — never rederived from `(g, K)`. It is a
                // lane like any other; that it agrees with `(g_out − K_out) mod A`
                // is a redundancy the tests check, not a definition.
                let a_out = match op {
                    CramOp::Add => (x.a + y.a).rem_euclid(a_mod),
                    CramOp::Sub => (x.a - y.a).rem_euclid(a_mod),
                    CramOp::Mul => x.a.checked_mul(y.a).ok_or_else(ov)?.rem_euclid(a_mod),
                    CramOp::Sqr => x.a.checked_mul(x.a).ok_or_else(ov)?.rem_euclid(a_mod),
                    CramOp::Neg => (-x.a).rem_euclid(a_mod),
                    CramOp::Id => x.a,
                    CramOp::Div | CramOp::Inv => unreachable!("filtered above"),
                };
                Ok((Winding::Known(k_out), a_out))
            }
            // The corridor discards magnitude by construction: the winding is
            // pinned to 0 and the anchor lane tracks the wrapped value.
            Topology::Corridor => Ok((Winding::Known(0), g_out.rem_euclid(a_mod))),
        }
    }

    /// Execute a program. Cannot leave residue space by construction: no arm
    /// of this loop calls [`Self::project`].
    pub fn exec(&mut self, prog: &[Instr]) -> Result<(), CramError> {
        for ins in prog {
            match ins {
                Instr::Load { dst, value } => self.load(*dst, *value)?,
                Instr::Apply { dst, a, b, schema } => {
                    self.check_reg(*dst)?;
                    self.check_reg(*a)?;
                    self.check_reg(*b)?;
                    let s = self.schema(schema)?;
                    let out = s.apply(&self.regs[*a].r, &self.regs[*b].r)?;
                    let (k, anchor) = self.propagate(&s, &self.regs[*a], &self.regs[*b])?;
                    let sigma = self.signature_of(&out, &k);
                    let topology = self.regs[*dst].topology;
                    self.regs[*dst] = Adelic {
                        r: out,
                        a: anchor,
                        k,
                        sigma,
                        topology,
                    };
                    self.ops_executed += 1;
                }
            }
        }
        Ok(())
    }
}

// ─── Configuration: each lane gets an operator ────────────────────────────

/// The channel a carry signature opens, per the aspect table. The signature is
/// read on the discriminating lanes {7, 11, 13} — Bridge, Shadow, Boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// (0,0,0) — conjunction. No lane carries.
    Neutral,
    /// (1,0,0) — bridge only. Semi-square / biquintile.
    Bridge,
    /// (0,1,0) — shadow only. Quintile / trine.
    Shadow,
    /// (1,1,0) — bridge + shadow. Sextile.
    BridgeShadow,
    /// (1,0,1) — bridge + boundary. Square / opposition.
    BridgeBoundary,
    /// Any triple outside the tabulated aspects.
    Other(u8, u8, u8),
}

impl Channel {
    pub fn of(sig: (u8, u8, u8)) -> Self {
        match sig {
            (0, 0, 0) => Channel::Neutral,
            (1, 0, 0) => Channel::Bridge,
            (0, 1, 0) => Channel::Shadow,
            (1, 1, 0) => Channel::BridgeShadow,
            (1, 0, 1) => Channel::BridgeBoundary,
            (a, b, c) => Channel::Other(a, b, c),
        }
    }
}

impl Cram {
    /// Configure the machine: one operator per lane, fixed for the machine's
    /// lifetime. This is the "configurable" in Configurable Residue Arithmetic
    /// Machine — the lane operator assignment *is* the configuration, not a
    /// per-instruction argument.
    pub fn configure(basis: &[u64], notation: &str, n_regs: usize) -> Result<Self, CramError> {
        let m = Cram::new(basis, n_regs);
        let s = m.schema(notation)?;
        let mut m = m;
        m.config = Some(s);
        Ok(m)
    }

    /// Configure over [`DISCRIMINATING_BASIS`].
    pub fn configured(notation: &str, n_regs: usize) -> Result<Self, CramError> {
        Self::configure(&DISCRIMINATING_BASIS, notation, n_regs)
    }

    /// The configured schema, if any.
    pub fn config(&self) -> Option<&Schema> {
        self.config.as_ref()
    }

    /// Apply the *configured* schema: `dst = schema(a, b)`, lane by lane.
    pub fn step(&mut self, dst: usize, a: usize, b: usize) -> Result<(), CramError> {
        self.check_reg(dst)?;
        self.check_reg(a)?;
        self.check_reg(b)?;
        let s = self.config.clone().ok_or(CramError::NotConfigured)?;
        let out = s.apply(&self.regs[a].r, &self.regs[b].r)?;
        let (k, anchor) = self.propagate(&s, &self.regs[a], &self.regs[b])?;
        let sigma = self.signature_of(&out, &k);
        let topology = self.regs[dst].topology;
        self.regs[dst] = Adelic {
            r: out,
            a: anchor,
            k,
            sigma,
            topology,
        };
        self.ops_executed += 1;
        Ok(())
    }

    /// Checklist step 5 — extract the Sqr carry signature on the
    /// discriminating lanes {7, 11, 13}.
    ///
    /// Read natively: the carry is computed from the lane residues the machine
    /// already holds. No projection, so this does not count as an exit.
    pub fn carry_signature(&self, reg: usize) -> Result<(u8, u8, u8), CramError> {
        self.check_reg(reg)?;
        let lane = |p: u64| -> u64 {
            self.basis
                .iter()
                .position(|&q| q == p)
                .map(|i| self.regs[reg].r[i])
                .unwrap_or(0)
        };
        let (r7, r11, r13) = (lane(7), lane(11), lane(13));
        Ok((
            u8::from(r7 * r7 >= 7),
            u8::from(r11 * r11 >= 11),
            u8::from(r13 * r13 >= 13),
        ))
    }

    /// The channel opened by a register's carry signature.
    pub fn channel(&self, reg: usize) -> Result<Channel, CramError> {
        Ok(Channel::of(self.carry_signature(reg)?))
    }

    /// Fraction of inputs for which the configured schema is defined, as
    /// `(numerator, denominator)`. Div/Inv lanes are partial: a lane mod `p`
    /// is defined on `(p-1)/p` of its inputs.
    pub fn validity(&self) -> Option<(u64, u64)> {
        self.config.as_ref().map(crate::cram_ops::schema_validity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defining property: one instruction, a different operator per lane.
    /// Verified lane by lane against hand-computed modular arithmetic.
    #[test]
    fn heterogeneous_schema_applies_a_different_operator_to_each_lane() {
        let mut m = Cram::discriminating(3);
        m.load(0, 20).unwrap();
        m.load(1, 6).unwrap();
        // A=Add, S=Sub, M=Mul, Q=Sqr, _=Id
        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "ASMQ_".into(),
        }])
        .unwrap();

        let a = [20 % 3, 20 % 5, 20 % 7, 20 % 11, 20 % 13];
        let b = [6 % 3, 6 % 5, 6 % 7, 6 % 11, 6 % 13];
        let want = [
            (a[0] + b[0]) % 3,     // Add on ground
            (a[1] + 5 - b[1]) % 5, // Sub on surface
            (a[2] * b[2]) % 7,     // Mul on bridge
            (a[3] * a[3]) % 11,    // Sqr on shadow (unary, ignores b)
            a[4],                  // Id on boundary
        ];
        assert_eq!(
            m.read(2).unwrap(),
            &want,
            "each lane must run its own operator"
        );
    }

    /// Direction matters — a schema and its reverse are different machines.
    #[test]
    fn schema_direction_is_not_symmetric() {
        let mut m = Cram::discriminating(3);
        let run = |m: &mut Cram, sch: &str| {
            m.load(0, 20).unwrap();
            m.load(1, 6).unwrap();
            m.exec(&[Instr::Apply {
                dst: 2,
                a: 0,
                b: 1,
                schema: sch.into(),
            }])
            .unwrap();
            m.read(2).unwrap().to_vec()
        };
        let fwd = run(&mut m, "ASMQ_");
        let rev = run(&mut m, "_QMSA");
        assert_ne!(fwd, rev, "reversing the schema must change the result");
    }

    /// Execution stays in residue space. The counter is the proof, and it can
    /// only be moved by `project`.
    #[test]
    fn execution_never_leaves_residue_space() {
        let mut m = Cram::discriminating(4);
        m.exec(&[
            Instr::Load { dst: 0, value: 41 },
            Instr::Load { dst: 1, value: 17 },
            Instr::Apply {
                dst: 2,
                a: 0,
                b: 1,
                schema: "AAMM_".into(),
            },
            Instr::Apply {
                dst: 3,
                a: 2,
                b: 1,
                schema: "MMAA_".into(),
            },
            Instr::Apply {
                dst: 0,
                a: 3,
                b: 2,
                schema: "QQQQQ".into(),
            },
        ])
        .unwrap();

        assert_eq!(m.ops_executed(), 3, "three schema applications ran");
        assert_eq!(
            m.projections(),
            0,
            "a program that never calls project() must record zero exits — \
             if this ever becomes nonzero, exec() has started reconstructing"
        );

        // The single explicit exit is counted.
        let _ = m.project(0).unwrap();
        assert_eq!(
            m.projections(),
            1,
            "project() is the only exit and is counted"
        );
    }

    /// DKAM is gated, not assumed: a basis containing 2 has rho = 2, which no
    /// degree-2 operator can sit below. This is why 2 is a parking lane and
    /// not part of the discriminating basis.
    #[test]
    fn dkam_gate_rejects_a_basis_whose_resonance_order_is_too_low() {
        let ok = Cram::discriminating(1);
        assert_eq!(ok.rho(), 3);
        assert!(ok.schema("MMMMM").is_ok(), "deg 2 < rho 3 must pass");

        let bad = Cram::new(&[2, 3, 5, 7, 11], 1);
        assert_eq!(bad.rho(), 2);
        match bad.schema("MMMMM") {
            Err(CramError::Op(CramOpError::DegreeViolation {
                max_degree, rho, ..
            })) => {
                assert_eq!((max_degree, rho), (2, 2), "deg 2 is not < rho 2");
            }
            other => panic!("basis containing 2 must fail DKAM, got {other:?}"),
        }
        // Degree-1 operators are still admissible on that basis.
        assert!(bad.schema("AAAAA").is_ok(), "deg 1 < rho 2 must still pass");
    }

    /// Lane roles are assigned from the prime, not from position.
    #[test]
    fn lanes_carry_roles_not_just_moduli() {
        let m = Cram::discriminating(1);
        assert_eq!(
            m.roles(),
            &[
                LaneRole::Ground,
                LaneRole::Surface,
                LaneRole::Bridge,
                LaneRole::Shadow,
                LaneRole::Boundary
            ]
        );
        assert_eq!(LaneRole::of(17), LaneRole::Extension(17));
    }

    /// Feed a value in, run, project back out — exact within the corridor.
    #[test]
    fn round_trips_exactly_within_the_corridor() {
        let m_prod: i128 = DISCRIMINATING_BASIS.iter().map(|&p| p as i128).product();
        assert_eq!(m_prod, 15015);
        let mut m = Cram::discriminating(3);
        let mut checked = 0;
        for v in (0..m_prod).step_by(97) {
            m.load(0, v).unwrap();
            assert_eq!(m.project(0).unwrap(), v, "v={v}");
            checked += 1;
        }
        assert!(
            checked > 100,
            "must actually sweep the corridor, got {checked}"
        );
    }

    // ─── Configuration: each lane gets an operator ─────────────────────────

    /// The machine is configured with one operator per lane, and `step` uses
    /// that configuration — the assignment is the machine's identity, not an
    /// argument passed per call.
    #[test]
    fn configured_machine_applies_its_own_per_lane_operators() {
        // Add ground, Sub surface, Mul bridge, Sqr shadow, Id boundary.
        let mut m = Cram::configured("ASMQ_", 3).unwrap();
        assert_eq!(m.config().unwrap().notation(), "ASMQ_");

        m.load(0, 20).unwrap();
        m.load(1, 6).unwrap();
        m.step(2, 0, 1).unwrap();

        let a = [20 % 3, 20 % 5, 20 % 7, 20 % 11, 20 % 13];
        let b = [6 % 3, 6 % 5, 6 % 7, 6 % 11, 6 % 13];
        assert_eq!(
            m.read(2).unwrap(),
            &[
                (a[0] + b[0]) % 3,
                (a[1] + 5 - b[1]) % 5,
                (a[2] * b[2]) % 7,
                (a[3] * a[3]) % 11,
                a[4],
            ],
            "step() must apply the CONFIGURED operator on each lane"
        );
        assert_eq!(m.ops_executed(), 1);
        assert_eq!(m.projections(), 0, "step() must not leave residue space");
    }

    /// An unconfigured machine refuses to step rather than defaulting.
    #[test]
    fn unconfigured_machine_refuses_to_step() {
        let mut m = Cram::discriminating(2);
        assert_eq!(m.step(1, 0, 0), Err(CramError::NotConfigured));
    }

    /// Checklist step 5: the Sqr carry signature is read on {7, 11, 13} from
    /// the lanes the machine already holds — natively, with no projection.
    #[test]
    fn carry_signature_is_read_natively_on_the_discriminating_lanes() {
        let mut m = Cram::discriminating(1);

        // 0 carries nowhere: 0*0 < p on every lane.
        m.load(0, 0).unwrap();
        assert_eq!(m.carry_signature(0).unwrap(), (0, 0, 0));
        assert_eq!(m.channel(0).unwrap(), Channel::Neutral);
        assert_eq!(m.projections(), 0, "reading the signature is not an exit");

        // Verify against the standalone extractor over a wide sweep, so the
        // machine's native read and the reference agree everywhere.
        let mut checked = 0;
        for v in 0..1000i128 {
            m.load(0, v).unwrap();
            let native = m.carry_signature(0).unwrap();
            let reference = crate::cram_ops::sqr_carry_signature(v as u64);
            assert_eq!(native, reference, "v={v}: native read must match reference");
            checked += 1;
        }
        assert_eq!(checked, 1000, "must sweep, not sample");
        assert_eq!(
            m.projections(),
            0,
            "the whole sweep stayed in residue space"
        );
    }

    /// Channels come from the aspect table; distinct signatures must not
    /// collapse onto one channel.
    #[test]
    fn channel_classification_matches_the_aspect_table() {
        assert_eq!(Channel::of((0, 0, 0)), Channel::Neutral);
        assert_eq!(Channel::of((1, 0, 0)), Channel::Bridge);
        assert_eq!(Channel::of((0, 1, 0)), Channel::Shadow);
        assert_eq!(Channel::of((1, 1, 0)), Channel::BridgeShadow);
        assert_eq!(Channel::of((1, 0, 1)), Channel::BridgeBoundary);
        assert_eq!(Channel::of((1, 1, 1)), Channel::Other(1, 1, 1));

        let tabulated = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0), (1, 0, 1)];
        let mut seen = std::collections::HashSet::new();
        for sig in tabulated {
            assert!(
                seen.insert(Channel::of(sig)),
                "{sig:?} collides with an earlier channel — the table would be lossy"
            );
        }
    }

    /// Div/Inv lanes are partial: validity is the product of (p-1)/p over
    /// exactly those lanes.
    #[test]
    fn validity_accounts_for_partial_division_lanes() {
        let total = Cram::configured("AAMMM", 1).unwrap();
        assert_eq!(total.validity(), Some((1, 1)), "no Div/Inv lane is total");

        // Div on bridge (7), Inv on shadow (11).
        let partial = Cram::configured("AADIM", 1).unwrap();
        assert_eq!(
            partial.validity(),
            Some((6 * 10, 7 * 11)),
            "one Div lane mod 7 and one Inv lane mod 11"
        );
    }

    // ─── The Adelic State Tuple ───────────────────────────────────────────

    /// The full basis, including 2 and 11, so Σ has both of its lane sources.
    const S6: [u64; 6] = [2, 3, 5, 7, 11, 13];

    /// The winding must report real magnitude, checked against ground truth at
    /// every step of a squaring chain. This is the property a residue signature
    /// structurally cannot have — and the one whose absence was the GSO defect.
    #[test]
    fn the_winding_tracks_real_magnitude_through_a_squaring_chain() {
        let mut m = Cram::discriminating(1);
        assert_eq!(m.modulus(), 15_015);
        assert_eq!(m.anchor(), 15_016);

        m.load(0, 3).unwrap();
        assert_eq!(
            m.winding(0).unwrap(),
            &Winding::Known(0),
            "3 is in the corridor"
        );

        let powers: [i128; 6] = [
            9,
            81,
            6_561,
            43_046_721,
            1_853_020_188_851_841,
            3_433_683_820_292_512_484_657_849_089_281,
        ];
        let mut windings = Vec::new();
        for (i, &want) in powers.iter().enumerate() {
            m.exec(&[Instr::Apply {
                dst: 0,
                a: 0,
                b: 0,
                schema: "QQQQQ".into(),
            }])
            .unwrap();
            let k = m.winding(0).unwrap().known().expect("Sqr is homogeneous");
            windings.push(k);
            // Ground truth, not a proxy: the state must name 3^(2^(i+1)).
            assert_eq!(
                m.project_integer(0).unwrap(),
                want,
                "squaring step {i} must name 3^{}",
                1 << (i + 1)
            );
        }

        // Growth is in the winding, and it is monotone once past the corridor.
        assert_eq!(&windings[..3], &[0, 0, 0], "3^2..3^8 fit inside M = 15015");
        assert!(windings[3] > 0, "3^16 must have left the corridor");
        assert!(
            windings[3..].windows(2).all(|w| w[1] > w[0]),
            "winding must strictly grow once outside the corridor: {windings:?}"
        );

        // C8 at the machine level: the next squaring cannot be represented, so
        // it is refused rather than wrapped, and the register is left intact.
        let before = m.state(0).unwrap().clone();
        assert_eq!(
            m.exec(&[Instr::Apply {
                dst: 0,
                a: 0,
                b: 0,
                schema: "QQQQQ".into()
            }]),
            Err(CramError::WindingOverflow)
        );
        assert_eq!(m.state(0).unwrap(), &before, "a refused op must not mutate");
    }

    /// Add, Sub, Mul and Neg must each agree with integer arithmetic, including
    /// across the corridor boundary and into negative windings.
    #[test]
    fn homogeneous_schemas_agree_with_integer_arithmetic() {
        let cases: [(i128, i128); 8] = [
            (0, 0),
            (1, 1),
            (15_014, 1),      // exactly onto the boundary
            (15_014, 15_014), // carry
            (30_030, 30_030), // both already wound
            (123_456, 987_654),
            (-5, 12), // negative winding
            (-15_015, -15_015),
        ];
        let mut carried = 0;
        let mut negative = 0;
        for (x, y) in cases {
            let mut m = Cram::discriminating(3);
            m.load(0, x).unwrap();
            m.load(1, y).unwrap();
            for (notation, want) in [
                ("AAAAA", x + y),
                ("SSSSS", x - y),
                ("MMMMM", x * y),
                ("NNNNN", -x),
                ("_____", x),
            ] {
                m.exec(&[Instr::Apply {
                    dst: 2,
                    a: 0,
                    b: 1,
                    schema: notation.into(),
                }])
                .unwrap();
                assert_eq!(
                    m.project_integer(2).unwrap(),
                    want,
                    "{notation} on ({x}, {y})"
                );
            }
            if x.rem_euclid(15_015) + y.rem_euclid(15_015) >= 15_015 {
                carried += 1;
            }
            if x < 0 || y < 0 {
                negative += 1;
            }
        }
        assert!(carried > 0, "cases must exercise the corridor carry");
        assert!(negative > 0, "cases must exercise negative windings");
    }

    /// The anchor lane is propagated lane-wise and is never rederived from
    /// `(g, K)`. That it nonetheless equals `(g − K) mod A` at every step is a
    /// redundancy — and the check that would catch the two drifting apart.
    #[test]
    fn the_anchor_lane_stays_consistent_with_the_winding_it_never_reads() {
        let mut m = Cram::discriminating(3);
        let mut checked = 0;
        for x in [0i128, 1, 15_014, 15_015, 123_456, -7] {
            for y in [1i128, 2, 15_015, 99_991] {
                m.load(0, x).unwrap();
                m.load(1, y).unwrap();
                for notation in ["AAAAA", "SSSSS", "MMMMM"] {
                    m.exec(&[Instr::Apply {
                        dst: 2,
                        a: 0,
                        b: 1,
                        schema: notation.into(),
                    }])
                    .unwrap();
                    let (anchor_lane, k) = {
                        let s = m.state(2).unwrap();
                        (s.a, s.k.known().unwrap())
                    };
                    let g = m.project(2).unwrap();
                    assert_eq!(
                        anchor_lane,
                        (g - k).rem_euclid(m.anchor()),
                        "anchor lane drifted at {notation}({x}, {y})"
                    );
                    // And the canonical part really is the CRT value: the
                    // anchored read and the destructive one must coincide.
                    let residues: Vec<(i128, i128)> = m
                        .read(2)
                        .unwrap()
                        .iter()
                        .zip(m.basis().iter())
                        .map(|(&r, &p)| (r as i128, p as i128))
                        .collect();
                    assert_eq!(
                        crate::k_elim::garner_reconstruct(&residues),
                        Some(g),
                        "anchored read must agree with Garner at {notation}({x}, {y})"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 6 * 4 * 3, "sweep must not shrink");
    }

    /// A heterogeneous schema is the defining CRAM move and it is not an integer
    /// operation. The winding is dropped, and the machine says so rather than
    /// carrying a number it cannot justify.
    #[test]
    fn a_heterogeneous_schema_drops_the_winding_and_names_why() {
        let mut m = Cram::discriminating(3);
        m.load(0, 41).unwrap();
        m.load(1, 17).unwrap();
        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "AMSQ_".into(),
        }])
        .unwrap();

        assert_eq!(
            m.winding(2).unwrap(),
            &Winding::Undefined(WindingLoss::Heterogeneous {
                notation: "AMSQ_".into()
            })
        );
        assert_eq!(m.signature(2).unwrap().sign, Sign::Unavailable);
        assert_eq!(m.signature(2).unwrap().bounds, None);
        assert_eq!(
            m.project_integer(2),
            Err(CramError::NoWinding(WindingLoss::Heterogeneous {
                notation: "AMSQ_".into()
            })),
            "there is no integer, so none may be returned"
        );

        // The residues are untouched and still perfectly valid — losing the
        // winding is not losing the value's residue identity.
        let lanes = m.read(2).unwrap();
        for (i, &p) in DISCRIMINATING_BASIS.iter().enumerate() {
            assert!(lanes[i] < p, "lane {i} still canonical mod {p}");
        }

        // The loss propagates: an operand with no winding cannot produce one.
        m.exec(&[Instr::Apply {
            dst: 0,
            a: 2,
            b: 1,
            schema: "AAAAA".into(),
        }])
        .unwrap();
        assert!(
            m.winding(0).unwrap().known().is_none(),
            "loss must propagate"
        );
    }

    /// Chimera 1, enforced. `Div` and `Inv` give `a·b⁻¹ mod p`, which is not
    /// `⌊a/b⌋` — so even a *homogeneous* Div schema loses the winding. Anything
    /// that wanted the integer quotient has to say so and pair it with a lift.
    #[test]
    fn modular_only_operators_lose_the_winding_even_when_homogeneous() {
        for (notation, code) in [("DDDDD", 'D'), ("IIIII", 'I')] {
            let mut m = Cram::discriminating(3);
            m.load(0, 41).unwrap();
            m.load(1, 17).unwrap();
            m.exec(&[Instr::Apply {
                dst: 2,
                a: 0,
                b: 1,
                schema: notation.into(),
            }])
            .unwrap();
            assert_eq!(
                m.winding(2).unwrap(),
                &Winding::Undefined(WindingLoss::ModularOnly { op: code }),
                "{notation} is modular-only"
            );
            assert!(m.project_integer(2).is_err(), "{notation} names no integer");
        }

        // Control: the same shape with an integer-meaningful operator keeps its
        // winding, so the rule is about the operator and not about homogeneity.
        let mut m = Cram::discriminating(3);
        m.load(0, 41).unwrap();
        m.load(1, 17).unwrap();
        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "MMMMM".into(),
        }])
        .unwrap();
        assert_eq!(m.project_integer(2).unwrap(), 41 * 17);
    }

    /// Every Σ field reads exactly one source. Perturbing one source must move
    /// its own field and nothing else.
    ///
    /// The probes are built so that only one input differs: adding `M/2` flips
    /// the 2-lane alone, adding `M/11` flips the 11-lane alone, and adding `M`
    /// flips the winding while leaving every lane identical.
    #[test]
    fn each_signature_field_reads_exactly_one_source() {
        let mut m = Cram::new(&S6, 2);
        assert_eq!(m.modulus(), 30_030);

        // Baseline: 110 — even, on the shadow (110 = 10·11), winding 0.
        m.load(0, 110).unwrap();
        let base = m.signature(0).unwrap();
        assert_eq!(base.parity, Parity::Even);
        assert_eq!(base.shadow, ShadowStatus::OnShadow);
        assert_eq!(base.sign, Sign::NonNegative);
        assert_eq!(base.bounds, Some((0, 30_030)));

        // Perturb the 2-lane only.
        m.load(1, 110 + 30_030 / 2).unwrap();
        let p = m.signature(1).unwrap();
        assert_eq!(
            m.read(0).unwrap()[1..],
            m.read(1).unwrap()[1..],
            "only the 2-lane may differ"
        );
        assert_ne!(m.read(0).unwrap()[0], m.read(1).unwrap()[0]);
        assert_eq!(p.parity, Parity::Odd, "parity must move");
        assert_eq!(p.shadow, base.shadow, "shadow must not");
        assert_eq!(p.sign, base.sign, "sign must not");
        assert_eq!(p.bounds, base.bounds, "bounds must not");

        // Perturb the 11-lane only.
        m.load(1, 110 + 30_030 / 11).unwrap();
        let s = m.signature(1).unwrap();
        let (a, b) = (m.read(0).unwrap().to_vec(), m.read(1).unwrap().to_vec());
        for i in 0..S6.len() {
            if S6[i] == 11 {
                assert_ne!(a[i], b[i], "the 11-lane must differ");
            } else {
                assert_eq!(a[i], b[i], "lane {i} must not");
            }
        }
        assert_eq!(s.shadow, ShadowStatus::OffShadow, "shadow must move");
        assert_eq!(s.parity, base.parity, "parity must not");
        assert_eq!(s.bounds, base.bounds, "bounds must not");

        // Perturb the winding only — every lane is bit-identical.
        m.load(1, 110 + 30_030).unwrap();
        let w = m.signature(1).unwrap();
        assert_eq!(m.read(0).unwrap(), m.read(1).unwrap(), "lanes identical");
        assert_eq!(w.bounds, Some((30_030, 60_060)), "bounds must move");
        assert_eq!(w.parity, base.parity, "parity must not");
        assert_eq!(w.shadow, base.shadow, "shadow must not");

        // Sign comes from the winding alone.
        m.load(1, -1).unwrap();
        assert_eq!(m.signature(1).unwrap().sign, Sign::Negative);
        assert_eq!(m.winding(1).unwrap(), &Winding::Known(-1));

        // A basis without 2 or 11 declines to report those fields rather than
        // reconstructing across lanes to manufacture them.
        let mut small = Cram::new(&[3, 5, 7], 1);
        small.load(0, 8).unwrap();
        assert_eq!(small.signature(0).unwrap().parity, Parity::Unavailable);
        assert_eq!(
            small.signature(0).unwrap().shadow,
            ShadowStatus::Unavailable
        );
    }

    /// The corridor topology pins the winding and wraps. It is a different
    /// domain, not a different encoding, and the difference is observable.
    #[test]
    fn the_corridor_topology_pins_the_winding_and_wraps() {
        let mut m = Cram::discriminating(3);
        for r in 0..3 {
            m.set_topology(r, Topology::Corridor).unwrap();
        }
        m.load(0, 20_000).unwrap();
        assert_eq!(m.winding(0).unwrap(), &Winding::Known(0), "pinned");
        assert_eq!(m.project(0).unwrap(), 20_000 - 15_015, "the value wrapped");

        m.load(1, 10_000).unwrap();
        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "AAAAA".into(),
        }])
        .unwrap();
        assert_eq!(m.winding(2).unwrap(), &Winding::Known(0), "still pinned");
        assert_eq!(
            m.project_integer(2).unwrap(),
            (20_000 + 10_000) % 15_015,
            "the corridor reports the wrapped value, not the magnitude"
        );

        // The same program on the integer line reports the magnitude instead —
        // so the topology is doing work, not decorating the state.
        let mut n = Cram::discriminating(3);
        n.load(0, 20_000).unwrap();
        n.load(1, 10_000).unwrap();
        n.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "AAAAA".into(),
        }])
        .unwrap();
        assert_eq!(n.project_integer(2).unwrap(), 30_000);
        assert_eq!(n.winding(2).unwrap(), &Winding::Known(1));
    }

    /// Exits are counted, and the *kind* of exit is counted separately: an
    /// anchored read leaves the residues intact, a Garner read consumes them.
    #[test]
    fn destructive_reads_are_counted_apart_from_anchored_ones() {
        let mut m = Cram::discriminating(3);
        m.load(0, 41).unwrap();
        m.load(1, 17).unwrap();

        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "MMMMM".into(),
        }])
        .unwrap();
        assert_eq!(m.projections(), 0);
        assert_eq!(m.project(2).unwrap(), (41 * 17) % 15_015);
        assert_eq!(m.projections(), 1, "an exit was taken");
        assert_eq!(m.destructive_reads(), 0, "but not a destructive one");

        // Heterogeneous: no winding, so the only way out is through Garner.
        m.exec(&[Instr::Apply {
            dst: 2,
            a: 0,
            b: 1,
            schema: "AMSQ_".into(),
        }])
        .unwrap();
        let g = m.project(2).unwrap();
        assert_eq!(m.projections(), 2);
        assert_eq!(
            m.destructive_reads(),
            1,
            "this one had to consume the residues"
        );
        assert!((0..15_015).contains(&g), "and it still returns a value");
    }

    /// The anchored read, over its whole domain, plus the one residue that can
    /// only mean corruption.
    ///
    /// `g = M` is unreachable for any consistent `(a, K)`, so it is refused
    /// rather than returned as if it were a value. The exhaustive half is the
    /// positive control: without it, refusal could be a function that refuses
    /// everything.
    #[test]
    fn the_anchored_read_is_exact_over_its_domain_and_refuses_the_impossible() {
        const M: i128 = 36;
        let mut checked = 0i128;
        for x in -500i128..500 {
            let g = x.rem_euclid(M);
            let k = x.div_euclid(M);
            let a = (g - k).rem_euclid(M + 1);
            assert_eq!(canonical_from(a, k, M), Ok(g), "x = {x}");
            // …and the pair really does name x, not just a consistent g.
            assert_eq!(g + k * M, x, "x = {x}");
            checked += 1;
        }
        assert_eq!(checked, 1_000, "sweep must not shrink");

        // The unreachable residue, forged directly.
        assert_eq!(
            canonical_from(M, 0, M),
            Err(CramError::InconsistentState { g: M, m: M })
        );
        assert_eq!(
            canonical_from(0, M, M),
            Err(CramError::InconsistentState { g: M, m: M })
        );

        // Overflow in the read itself is refused, not wrapped.
        assert_eq!(
            canonical_from(i128::MAX, 1, M),
            Err(CramError::WindingOverflow)
        );
    }
}
