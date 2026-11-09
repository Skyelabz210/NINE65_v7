#ifndef NINE65_H
#define NINE65_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct KioskHandle KioskHandle;

/* Full hash preimage. duration_nanos is informational and is not hashed. */
typedef struct {
    uint32_t version;
    uint8_t hash[32];
    uint64_t unit_id;
    uint64_t fold_generation;
    uint64_t final_entropy;
    uint64_t timestamp_nanos;
    uint64_t operations_performed;
    uint64_t duration_nanos;
    uint8_t unit_type;
    uint8_t valid;
} Nine65ReceiptV2;

/* Moduli must be odd, >1 and <2^63. Invalid parameters return NULL. */
KioskHandle *nine65_kiosk_create_bullet(uint64_t id, const uint64_t *moduli,
                                     size_t count, uint64_t seed);
KioskHandle *nine65_kiosk_create_capsule(uint64_t id, const uint64_t *moduli,
                                      size_t count, uint64_t seed, uint64_t operations);
KioskHandle *nine65_kiosk_create_fuse(uint64_t id, const uint64_t *moduli,
                                   size_t count, uint64_t seed, uint64_t lifetime_nanos);
int32_t nine65_kiosk_load(KioskHandle *handle, const uint64_t *data, size_t count);
int32_t nine65_kiosk_checked_mul(KioskHandle *handle, size_t index, uint64_t a,
                               uint64_t b, uint64_t modulus, uint64_t *result);
int32_t nine65_kiosk_checked_add(KioskHandle *handle, size_t index, uint64_t a,
                               uint64_t b, uint64_t modulus, uint64_t *result);
int32_t nine65_kiosk_status(const KioskHandle *handle);
uint64_t nine65_kiosk_remaining_ops(const KioskHandle *handle);
int32_t nine65_kiosk_destroy_v2(KioskHandle *handle, Nine65ReceiptV2 *receipt);
/* Hash/data consistency only; this does not authenticate a remote sender. */
int32_t nine65_receipt_verify_v2(const Nine65ReceiptV2 *receipt);
void nine65_kiosk_free(KioskHandle *handle);

#ifdef __cplusplus
}
#endif
#endif
