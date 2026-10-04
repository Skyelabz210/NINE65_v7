# Issue #18: Security audit - constant-time verification and side-channel hardening

- state: open
- labels: (none)
- created: 2026-03-02T16:41:23Z  updated: 2026-09-04T11:07:36Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/18

---

## Summary
Comprehensive security audit of all cryptographic code paths. Verify constant-time behavior in Montgomery, K-Elimination, NTT, and key operations. Run GRO timing gate validation.

## Tasks
- [ ] Verify constant-time Montgomery multiplication
- [ ] Audit K-Elimination for timing leaks
- [ ] Validate NTT constant-time properties
- [ ] Test GRO timing gates on keygen and decrypt
- [ ] Run test_security_hardening.sh and fix any failures
- [ ] Verify allow_insecure blocked in release builds

## Component
security