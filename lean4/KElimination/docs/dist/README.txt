MANA FHE Benchmark - Early Access Binary
=========================================

PROPRIETARY SOFTWARE - ALL RIGHTS RESERVED
Copyright (c) 2026 QMNF Advanced Mathematics

This is a stripped benchmark binary for independent performance validation.
The K-Elimination theorem (MIT licensed) is separate from this proprietary FHE system.

USAGE
-----
Linux x86-64 only:

    chmod +x mana_fhe_benchmark
    ./mana_fhe_benchmark

The benchmark runs automatically and displays:
  - Montgomery multiplication throughput
  - NTT operations (N=1024)
  - FHE operations (encrypt, decrypt, homomorphic add/mul)
  - QMNF Dual-Track Arithmetic metrics

EXPECTED OUTPUT
---------------
You should see results like:
  - Homomorphic Add:  ~50 microseconds
  - Homomorphic Mul:  <500 microseconds
  - Encrypt:          <1 millisecond
  - No bootstrapping required for deep circuits

SYSTEM REQUIREMENTS
-------------------
- Linux x86-64 (tested on Debian 13, Ubuntu 22.04+)
- glibc 2.31 or later
- No additional dependencies

FEEDBACK
--------
Report benchmark results to: founder@hackfate.us
Subject: MANA FHE Benchmark Results

Include:
- CPU model (cat /proc/cpuinfo | grep "model name" | head -1)
- Full benchmark output
- Any issues encountered

LICENSE NOTICE
--------------
This binary is provided for evaluation purposes only.
Redistribution, reverse engineering, or commercial use is prohibited.
The K-Elimination theorem (github.com/Skyelabz210/k-elimination-lean4) remains MIT licensed.

---
QMNF Advanced Mathematics | January 2026
