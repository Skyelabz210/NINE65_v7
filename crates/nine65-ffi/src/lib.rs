//! # NINE65 FFI — C API for Kiosk Computation Units
//!
//! Provides a C-compatible API for creating, using, and destroying
//! NINE65 Kiosk units from any language with C FFI support.
//!
//! ## Safety
//!
//! This crate is the ONLY place in the NINE65 workspace that uses `unsafe`.
//! All FFI boundary code follows strict safety invariants documented on
//! each function.
//!
//! ## Lifecycle
//!
//! ```text
//! nine65_kiosk_create_bullet()  → handle
//! nine65_kiosk_load()           → load data
//! nine65_kiosk_checked_mul()    → perform operations
//! nine65_kiosk_destroy()        → self-destruct + receipt
//! nine65_kiosk_free()           → release memory
//! ```

use std::ptr;

use nine65::kiosk::unit::{KioskLifecycle, KioskUnit};
use nine65::kiosk::receipt::ReceiptVerifier;

/// Opaque handle to a kiosk unit.
pub struct KioskHandle {
    unit: KioskUnit,
}

/// Destruction receipt returned to callers.
#[repr(C)]
pub struct FfiDestructionReceipt {
    /// SHA-256 hash bytes (32 bytes)
    pub hash: [u8; 32],
    /// Unit ID
    pub unit_id: u64,
    /// Operations performed
    pub operations_performed: u64,
    /// Destruction duration in nanoseconds
    pub duration_nanos: u64,
    /// Whether receipt is valid (1 = valid, 0 = invalid/no receipt)
    pub valid: u8,
}

/// Create a Bullet (single-use) kiosk unit.
///
/// # Safety
/// - `moduli` must point to `num_moduli` valid u64 values
/// - Caller must eventually free the handle with `nine65_kiosk_free`
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_create_bullet(
    id: u64,
    moduli: *const u64,
    num_moduli: usize,
    seed: u64,
) -> *mut KioskHandle {
    if moduli.is_null() || num_moduli == 0 {
        return ptr::null_mut();
    }
    let moduli_slice = std::slice::from_raw_parts(moduli, num_moduli);
    let unit = KioskUnit::bullet(id, moduli_slice, seed);
    Box::into_raw(Box::new(KioskHandle { unit }))
}

/// Create a Capsule (multi-use) kiosk unit.
///
/// # Safety
/// - `moduli` must point to `num_moduli` valid u64 values
/// - Caller must eventually free the handle with `nine65_kiosk_free`
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_create_capsule(
    id: u64,
    moduli: *const u64,
    num_moduli: usize,
    seed: u64,
    max_operations: u64,
) -> *mut KioskHandle {
    if moduli.is_null() || num_moduli == 0 {
        return ptr::null_mut();
    }
    let moduli_slice = std::slice::from_raw_parts(moduli, num_moduli);
    let unit = KioskUnit::capsule(id, moduli_slice, seed, max_operations);
    Box::into_raw(Box::new(KioskHandle { unit }))
}

/// Create a Fuse (time-limited) kiosk unit.
///
/// # Safety
/// - `moduli` must point to `num_moduli` valid u64 values
/// - Caller must eventually free the handle with `nine65_kiosk_free`
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_create_fuse(
    id: u64,
    moduli: *const u64,
    num_moduli: usize,
    seed: u64,
    lifetime_nanos: u64,
) -> *mut KioskHandle {
    if moduli.is_null() || num_moduli == 0 {
        return ptr::null_mut();
    }
    let moduli_slice = std::slice::from_raw_parts(moduli, num_moduli);
    let unit = KioskUnit::fuse(id, moduli_slice, seed, lifetime_nanos);
    Box::into_raw(Box::new(KioskHandle { unit }))
}

/// Load data into a kiosk unit.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
/// - `data` must point to `num_limbs` valid u64 values
///
/// # Returns
/// 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_load(
    handle: *mut KioskHandle,
    data: *const u64,
    num_limbs: usize,
) -> i32 {
    if handle.is_null() || data.is_null() {
        return 0;
    }
    let h = &mut *handle;
    let data_slice = std::slice::from_raw_parts(data, num_limbs);
    if h.unit.load(data_slice) { 1 } else { 0 }
}

/// Perform a checked multiplication.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
/// - `result_out` must point to a valid u64
///
/// # Returns
/// 1 on success, 0 on failure (fuse triggered, attack detected, etc.)
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_checked_mul(
    handle: *mut KioskHandle,
    index: usize,
    a: u64,
    b: u64,
    modulus: u64,
    result_out: *mut u64,
) -> i32 {
    if handle.is_null() || result_out.is_null() {
        return 0;
    }
    let h = &mut *handle;
    match h.unit.checked_mul(index, a, b, modulus) {
        Some(r) => {
            *result_out = r;
            1
        }
        None => 0,
    }
}

/// Perform a checked addition.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
/// - `result_out` must point to a valid u64
///
/// # Returns
/// 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_checked_add(
    handle: *mut KioskHandle,
    index: usize,
    a: u64,
    b: u64,
    modulus: u64,
    result_out: *mut u64,
) -> i32 {
    if handle.is_null() || result_out.is_null() {
        return 0;
    }
    let h = &mut *handle;
    match h.unit.checked_add(index, a, b, modulus) {
        Some(r) => {
            *result_out = r;
            1
        }
        None => 0,
    }
}

/// Get the unit status.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
///
/// # Returns
/// 0 = Ready, 1 = Active, 2 = Triggered, 3 = Destroyed, 4 = Compromised
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_status(handle: *const KioskHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let h = &*handle;
    match h.unit.status() {
        nine65::kiosk::unit::UnitStatus::Ready => 0,
        nine65::kiosk::unit::UnitStatus::Active => 1,
        nine65::kiosk::unit::UnitStatus::Triggered => 2,
        nine65::kiosk::unit::UnitStatus::Destroyed => 3,
        nine65::kiosk::unit::UnitStatus::Compromised => 4,
    }
}

/// Get remaining operations.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_remaining_ops(handle: *const KioskHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    let h = &*handle;
    h.unit.remaining_operations()
}

/// Destroy the kiosk unit and get a receipt.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function
/// - `receipt_out` must point to a valid FfiDestructionReceipt
///
/// # Returns
/// 1 if destruction succeeded, 0 if already destroyed
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_destroy(
    handle: *mut KioskHandle,
    receipt_out: *mut FfiDestructionReceipt,
) -> i32 {
    if handle.is_null() || receipt_out.is_null() {
        return 0;
    }
    let h = &mut *handle;
    match h.unit.destroy() {
        Some(receipt) => {
            let out = &mut *receipt_out;
            out.hash.copy_from_slice(receipt.hash.as_bytes());
            out.unit_id = receipt.data.unit_id;
            out.operations_performed = receipt.data.operations_performed;
            out.duration_nanos = receipt.duration_nanos;
            out.valid = 1;
            1
        }
        None => {
            let out = &mut *receipt_out;
            out.valid = 0;
            0
        }
    }
}

/// Free a kiosk handle.
///
/// # Safety
/// - `handle` must be a valid pointer from a create function, or null
/// - Must not be called twice on the same handle
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_free(handle: *mut KioskHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Verify a destruction receipt.
///
/// # Safety
/// - `receipt` must point to a valid FfiDestructionReceipt with valid=1
///
/// # Returns
/// 1 if receipt verifies, 0 if not
#[no_mangle]
pub unsafe extern "C" fn nine65_receipt_verify(
    receipt: *const FfiDestructionReceipt,
) -> i32 {
    if receipt.is_null() {
        return 0;
    }
    let r = &*receipt;
    if r.valid != 1 {
        return 0;
    }

    let receipt_data = nine65::kiosk::receipt::ReceiptData {
        unit_id: r.unit_id,
        fold_generation: 1, // Default for verification
        final_entropy: 0,
        timestamp_nanos: 0,
        operations_performed: r.operations_performed,
        unit_type: 0,
    };

    let hash = nine65::kiosk::receipt::ReceiptHash::from_bytes(r.hash);
    if ReceiptVerifier::verify(&receipt_data, &hash) { 1 } else { 0 }
}
