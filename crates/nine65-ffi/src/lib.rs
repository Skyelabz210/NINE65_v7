//! # NINE65 FFI — C API for Kiosk Computation Units
//!
//! Provides a C-compatible API for creating, using, and destroying
//! NINE65 Kiosk units from any language with C FFI support.
//!
//! ## Safety
//!
//! The raw-pointer boundary requires the safety invariants documented on
//! each exported function.
//!
//! Invalid modulus values are rejected before calling arithmetic constructors
//! or operations. Callers must still satisfy each raw-pointer safety contract.
//! Panics/OOM aborting the process and invalid foreign pointers are not turned
//! into recoverable errors by this API.
//!
//! The version-2 receipt includes the complete hash preimage. The legacy
//! version-1 layout is retained for ABI compatibility and cannot verify the
//! full destruction record. Hash consistency is not remote attestation.
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

fn valid_moduli(moduli: &[u64]) -> bool {
    moduli
        .iter()
        .all(|&q| q > 1 && q & 1 == 1 && q < (1u64 << 63))
}

use nine65::kiosk::receipt::ReceiptVerifier;
use nine65::kiosk::unit::{KioskLifecycle, KioskUnit};

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
    if !valid_moduli(moduli_slice) {
        return ptr::null_mut();
    }
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
    if !valid_moduli(moduli_slice) {
        return ptr::null_mut();
    }
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
    if !valid_moduli(moduli_slice) {
        return ptr::null_mut();
    }
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
    if h.unit.load(data_slice) {
        1
    } else {
        0
    }
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
    if handle.is_null() || result_out.is_null() || modulus <= 1 {
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
    if handle.is_null() || result_out.is_null() || modulus <= 1 {
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
/// # Known limitation — partial-field verification
/// This function reconstructs `ReceiptData` from the fields carried on the
/// FFI-visible `FfiDestructionReceipt` (`unit_id`, `operations_performed`)
/// and fills the remaining fields the original receipt hash was computed
/// over — `fold_generation`, `final_entropy`, `timestamp_nanos`,
/// `unit_type` — with fixed placeholder values (`1`, `0`, `0`, `0`), not the
/// values the destroyed unit actually had. The hash comparison therefore
/// only verifies `unit_id`/`operations_performed` against a receipt that
/// happens to have been created with those exact placeholder values for the
/// other four fields; it does not verify the receipt against the unit's
/// real `fold_generation`/`final_entropy`/`timestamp_nanos`/`unit_type` at
/// destruction time. Do not treat a `1` return as proof the receipt matches
/// the full original destruction record — only that the two visible fields
/// are consistent with a receipt built from the placeholder remainder.
///
/// # Safety
/// - `receipt` must point to a valid FfiDestructionReceipt with valid=1
///
/// # Returns
/// 1 if the (partial, see above) verification succeeds, 0 if not
#[no_mangle]
pub unsafe extern "C" fn nine65_receipt_verify(receipt: *const FfiDestructionReceipt) -> i32 {
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
    if ReceiptVerifier::verify(&receipt_data, &hash) {
        1
    } else {
        0
    }
}

/// Versioned receipt carrying every field covered by the destruction hash.
/// Duration is informational and is not included in that hash.
#[repr(C)]
#[derive(Default)]
pub struct FfiDestructionReceiptV2 {
    pub version: u32,
    pub hash: [u8; 32],
    pub unit_id: u64,
    pub fold_generation: u64,
    pub final_entropy: u64,
    pub timestamp_nanos: u64,
    pub operations_performed: u64,
    pub duration_nanos: u64,
    pub unit_type: u8,
    pub valid: u8,
}

/// Destroy a unit and export a complete version-2 receipt.
///
/// # Safety
/// The handle must be live and exclusively owned for this call; receipt_out
/// must point to writable storage for the full FfiDestructionReceiptV2.
#[no_mangle]
pub unsafe extern "C" fn nine65_kiosk_destroy_v2(
    handle: *mut KioskHandle,
    receipt_out: *mut FfiDestructionReceiptV2,
) -> i32 {
    if receipt_out.is_null() {
        return 0;
    }
    (*receipt_out).valid = 0;
    if handle.is_null() {
        return 0;
    }
    let Some(receipt) = (*handle).unit.destroy() else {
        return 0;
    };
    *receipt_out = FfiDestructionReceiptV2 {
        version: 2,
        hash: *receipt.hash.as_bytes(),
        unit_id: receipt.data.unit_id,
        fold_generation: receipt.data.fold_generation,
        final_entropy: receipt.data.final_entropy,
        timestamp_nanos: receipt.data.timestamp_nanos,
        operations_performed: receipt.data.operations_performed,
        duration_nanos: receipt.duration_nanos,
        unit_type: receipt.data.unit_type,
        valid: 1,
    };
    1
}

/// Check every hashed field of a version-2 destruction record.
/// This checks data/hash consistency; it does not authenticate its sender.
///
/// # Safety
/// receipt must be null or point to a readable FfiDestructionReceiptV2.
#[no_mangle]
pub unsafe extern "C" fn nine65_receipt_verify_v2(receipt: *const FfiDestructionReceiptV2) -> i32 {
    if receipt.is_null() {
        return 0;
    }
    let receipt = &*receipt;
    if receipt.version != 2 || receipt.valid != 1 {
        return 0;
    }
    let data = nine65::kiosk::receipt::ReceiptData {
        unit_id: receipt.unit_id,
        fold_generation: receipt.fold_generation,
        final_entropy: receipt.final_entropy,
        timestamp_nanos: receipt.timestamp_nanos,
        operations_performed: receipt.operations_performed,
        unit_type: receipt.unit_type,
    };
    let hash = nine65::kiosk::receipt::ReceiptHash::from_bytes(receipt.hash);
    i32::from(ReceiptVerifier::verify(&data, &hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_receipt_roundtrip_rejects_changed_fields() {
        unsafe {
            let moduli = [97, 101, 103];
            let handle = nine65_kiosk_create_capsule(42, moduli.as_ptr(), moduli.len(), 7, 10);
            assert!(!handle.is_null());
            assert_eq!(nine65_kiosk_load(handle, [1, 2, 3].as_ptr(), 3), 1);
            let mut result = 0;
            assert_eq!(
                nine65_kiosk_checked_mul(handle, 0, 6, 7, 97, &mut result),
                1
            );
            assert_eq!(result, 42);
            let mut receipt = FfiDestructionReceiptV2::default();
            assert_eq!(nine65_kiosk_destroy_v2(handle, &mut receipt), 1);
            assert_eq!(nine65_kiosk_status(handle), 3);
            assert_eq!(nine65_receipt_verify_v2(&receipt), 1);
            receipt.fold_generation ^= 1;
            assert_eq!(nine65_receipt_verify_v2(&receipt), 0);
            receipt.fold_generation ^= 1;
            receipt.unit_type ^= 1;
            assert_eq!(nine65_receipt_verify_v2(&receipt), 0);
            nine65_kiosk_free(handle);
        }
    }

    #[test]
    fn invalid_moduli_are_rejected_before_constructing_a_unit() {
        unsafe {
            for modulus in [0, 1, 2, 1u64 << 63, u64::MAX] {
                assert!(nine65_kiosk_create_bullet(1, &modulus, 1, 7).is_null());
                assert!(nine65_kiosk_create_capsule(1, &modulus, 1, 7, 10).is_null());
                assert!(nine65_kiosk_create_fuse(1, &modulus, 1, 7, 100).is_null());
            }
        }
    }

    #[test]
    fn invalid_operation_modulus_does_not_change_output() {
        unsafe {
            let modulus = 97;
            let handle = nine65_kiosk_create_capsule(1, &modulus, 1, 7, 10);
            assert_eq!(nine65_kiosk_load(handle, [1].as_ptr(), 1), 1);
            let mut output = 99;
            for modulus in [0, 1] {
                assert_eq!(
                    nine65_kiosk_checked_mul(handle, 0, 6, 7, modulus, &mut output),
                    0
                );
                assert_eq!(
                    nine65_kiosk_checked_add(handle, 0, 6, 7, modulus, &mut output),
                    0
                );
                assert_eq!(output, 99);
            }
            nine65_kiosk_free(handle);
        }
    }

    #[test]
    fn null_and_repeated_destruction_fail_cleanly() {
        unsafe {
            let mut receipt = FfiDestructionReceiptV2::default();
            assert_eq!(nine65_kiosk_destroy_v2(ptr::null_mut(), &mut receipt), 0);
            assert_eq!(nine65_receipt_verify_v2(ptr::null()), 0);
            let modulus = 97;
            let handle = nine65_kiosk_create_bullet(1, &modulus, 1, 7);
            assert_eq!(nine65_kiosk_destroy_v2(handle, &mut receipt), 1);
            assert_eq!(nine65_kiosk_destroy_v2(handle, &mut receipt), 0);
            assert_eq!(receipt.valid, 0);
            nine65_kiosk_free(handle);
        }
    }
}
