# Restored transduction boundary fixes

The changes from merged PRs #170/#171 and their reviewed follow-up were absent
from current remote main. This patch restores typed constructor refusals,
fallible reverse verification, and positive/boundary fixtures from local main
`47fc49c`. It corrects the claims about the staged scalar rank calculation.

The restored code does not admit a production lift witness or satisfy the
lane-parallel architecture gate. The newer #179 Garner implementation and
all its overflow/coprimality regressions remain intact. Only the older positive
modulus guard and test-only call counter are restored in `k_elim.rs`.

The complete package runs 640 tests with no failures or ignores. Strict package
Clippy and the no-default-features build pass. Exact inputs/logs are in
`result.json`; the broader ciphertext and security gates remain open.
