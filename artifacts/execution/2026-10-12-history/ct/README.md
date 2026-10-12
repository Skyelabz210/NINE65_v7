# Restored October 7 constant-time fixes

Remote main did not contain the commits from merged PRs #168/#169. The
restoration copies their final reviewed reducer, rounding, sign-encoding and
compatibility changes from local main `47fc49c`. It preserves the later #179
winding and Garner repairs and #180 dependency versions.

`result.json` binds the current inputs and fresh logs. All 46 RNS arithmetic
tests, the exhaustive modulus-switch case, and strict package Clippy pass.
Four selected cases are ignored. No new timing or release acceptance is
asserted. The nine default-suite correctness failures remain separate gates.
