#include "nine65.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const uint64_t moduli[] = {97, 101, 103};
    const uint64_t data[] = {1, 2, 3};
    KioskHandle *unit = nine65_kiosk_create_capsule(42, moduli, 3, 7, 10);
    assert(unit != NULL);
    assert(nine65_kiosk_load(unit, data, 3) == 1);
    uint64_t result = 0;
    assert(nine65_kiosk_checked_mul(unit, 0, 6, 7, 97, &result) == 1);
    assert(result == 42);
    Nine65ReceiptV2 receipt = {0};
    assert(nine65_kiosk_destroy_v2(unit, &receipt) == 1);
    assert(nine65_receipt_verify_v2(&receipt) == 1);
    receipt.operations_performed ^= 1;
    assert(nine65_receipt_verify_v2(&receipt) == 0);
    nine65_kiosk_free(unit);
    puts("C ABI compute, destruction and full receipt verification passed");
    return 0;
}
