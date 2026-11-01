# Constant-time posture of PublicRefreshCircuit

Current routing: [public refresh status](../PUBLIC_REFRESH_STATUS.md).

Constant-time posture of `public_refresh_circuit.rs` is not established.

No dudect run, gate, or timing contrast scoped to this circuit is included in this change. The carry extraction (`SplitDigitEvaluator::evaluate_prepared_with_progress`), the restoration add, the slot return, and the return key switch are the natural targets. Their variable-time dependencies are not inventoried by measurement here.

Adjacent findings are not inherited, in either direction:

* Historical F-2 measured `mod_switch_down_dual` at 2.96× on an older kernel (`docs/F2_SCOPE_2026-08-25.md`). That document's §8 says the division timing leak was later rewritten and that the semantic replacement of the function is still open. This circuit's note does not re-measure that function and does not claim the refresh path avoids it.
* Other open constant-time work, including issue #72, stays open for its own code. A percentage measured on `extract_k` is not a result about this circuit unless a report names this circuit and the commit.

The explicit non-claim: side-channel resistance of the research refresh is not established. Closing it requires a CT report whose measurements are taken on this path, plus either a fix or a written exclusion of the variable-time calls that remain.
