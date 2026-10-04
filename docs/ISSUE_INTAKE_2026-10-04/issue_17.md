# Issue #17: Enable Python bindings via PyO3 (nine65-python crate)

- state: open
- labels: (none)
- created: 2026-03-02T16:32:58Z  updated: 2026-09-04T11:06:36Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/17

---

## Summary
The nine65-python crate exists but is excluded from the build. Complete the PyO3 bindings so Python users can access FHE operations natively.

## Tasks
- [ ] Fix maturin build configuration
- [ ] Expose encrypt/decrypt/mul operations to Python
- [ ] Add Python-side key generation helpers
- [ ] Create Python test suite with pytest
- [ ] Write Python quickstart documentation
- [ ] Publish to PyPI (test index first)

## Component
sdk-bindings