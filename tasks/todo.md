# Technical packet execution checklist

- [x] Reconcile current remote HEAD and audited commit; hash available sources.
- [x] Preserve supplied packet and record missing evidence explicitly.
- [x] Run release workspace tests and record per-target results (31 failures; not green).
- [x] Complete independent capacity and witness admission corrections; test them.
- [x] Add and exercise reconstruction/product source gates (full gate remains red).
- [x] Update claims and publish an exact phase/gate status report.
- [x] Analyze all 16 follow-up attachments, hash originals, and reproduce model
      admission failures and exact arithmetic witnesses.
- [ ] T1/T2 recumbent port: source now supplied; blocked on demonstrated model
      defects and the general rounded-division/signed-lift/encrypted-carry contract.
- [ ] T3 Safe Basis integration: blocked on noncoprime adjacency construction.
- [ ] T5 optional tightening: not applicable before T2/T3 pass.
- [ ] T6 proofs/stress/external artifacts: blocked on construction and artifacts.
- [ ] Release: all packet gates green on one commit (currently blocked).
