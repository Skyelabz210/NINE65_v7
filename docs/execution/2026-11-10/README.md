# Parameter and security-evidence packet

Source snapshot: `7ada6503634a824e80bc4bcfd6231ad0178d7ed3`.
Current capability and claim routing: [public-refresh status](../../PUBLIC_REFRESH_STATUS.md).

Concurrent main integration reached `676c4ec68ec497ff5ef2bbc4697393ec9090a7bc`
before handoff and changed four source-bound files. Fresh key-free exports at
that commit confirm identical parameter/distribution data and graph relations
with a newly bound fingerprint. The `main676-*` orchestration artifacts record
those executions. Rust tests and external-cost results retain their original
`7ada650` source; no newer encrypted run is claimed.

On integration with main `3901f3b`, the exporter and distribution controls default
to the existing `main676-parameter-distributions.json` supplement. That snapshot
continues to match every bound source file. The original `7ada650` packet is
unchanged; checking it against newer runtime files correctly fails the source
binding instead of silently treating historical evidence as current.

Start with the [decomposed execution plan](PARAMETER_SECURITY_EXECUTION_PLAN.md).
The three focused reports contain their own commands, results, assumptions and
remaining work:

* [Exact parameters and distribution laws](PARAMETER_DISTRIBUTION_EVIDENCE.md).
* [Public key graph and reduced execution checks](PUBLIC_KEY_GRAPH_EVIDENCE.md).
* [Pinned external estimator diagnostics](EXTERNAL_ESTIMATOR_EVIDENCE.md).

The named RNS Work tuples have exact Q widths 119, 119, 146 and 175 bits. Their
separate legacy Clockwork bootstrap tuples have widths 146, 146, 177 and 206.
Native research domains are Work N8192/Q119, Source N8192/Q60/H96 and Outer
N32768/Q650. The return receiver reuses the N8192 Work secret in the N32768
ring over the four-prime Work modulus; it is not a fresh dense N32768 secret.
These numbers describe dimensions and modulus widths, not security levels.

The native graph has 659 polynomial ciphertexts in seven relations. Its 40
return ciphertexts expose 160 degree-8192 channels sharing the Work secret.
These are publication counts, not independent LWE samples. Both self-key
relations and the W→S→B→W cycle remain confidentiality obligations. The exact
coefficient laws distinguish `%3` ternary, rejection ternary, fixed balanced
sparse supports, and CBD(eta); nominal distribution names do not substitute
for those facts.

Raw public data, source hashes, logs and status manifests are under
[`artifacts/execution/2026-11-10`](../../../artifacts/execution/2026-11-10/).
The orchestration subdirectory records live branch/PR/issue inspection and
focused claim controls. Historical evidence and existing production gates
are preserved.

Confidentiality of the related-key setup is not established. External
parameter attestation is not obtained. This packet does not claim production
admission, a new native encrypted five-cycle execution, a probabilistic
decryption-failure bound, or constant-time behavior. The external estimates
are only the selected marginal diagnostics described in their report.
