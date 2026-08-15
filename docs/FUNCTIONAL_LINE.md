# Functional FHE line

This checkout is the preserved functional line for NINE65 development. It is based on the current v7 accelerated HEAD (`9c76db9`) and lives on branch `functional-v7-fhe` in a separate worktree. The experimental v7 branch and repository history remain unchanged.

The functional line keeps the production MANA/UNHAL path enabled by default while keeping Rayon opt-in. The current production route is:

```text
NINE65 FHE hot path -> UNHAL lane dispatcher -> MANA deterministic lane executor
```

The line is intended for correctness, secure-profile benchmarking, and integration work. CRAM, parameter experiments, and other research changes remain in the experimental v7 line until they are promoted deliberately.

The stable Clockwork foundation is tagged `v7.0.0-bootstrap-complete`. A direct cherry-pick of the later MANA wiring commits onto that tag was not accepted automatically because the intervening v7 changes altered the same `rns_fhe.rs` regions. The functional copy therefore uses the already-integrated current v7 path rather than risking an incomplete or mixed patch.

The v6 repository remains preserved on its own `functional-v7-mana-unhal` branch for further porting work. Its MANA/UNHAL adapter APIs differ materially from the current v7 lane dispatcher, so it should not be overwritten with a blind patch.
