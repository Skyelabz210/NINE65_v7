# PR #167 hosted artifacts for `57af1de`

Source head: `57af1de6a08803f8893f23f00f446a1728d8e69b`

* [Comparative harness run 37672722619](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37672722619) passed. The result retains the expected `legacy.mul_ct=false` and `refused-#135` fields; all supported checks and both requested depth entries pass.
* [V7 scale sweep run 37672722502](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37672722502) passed both quick cases with `build_profile: "debug"`, complete depth, and no operation correctness failures.
* [Fuzz Smoke run 37672722486](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37672722486) retains the three failing inputs below. NTT and K-Elimination fuzz targets pass.
* [CT verification run 37672722432](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37672722432) source and functional report is included. The blocking dudect job was still running when these artifacts were downloaded; its measurements will be added when complete.

The raw fuzz input SHA-256 values are:

* Deserialize, six bytes: `9b16aa807cfea36f2e02b95e230a72d17daaa9817cf4f51d18ee59af49a02a8a`
* Encrypt/decrypt, 16 bytes: `fe445a40befe256d87ee065d58531e9925d677a2a00369090a6eb638c260aaa3`
* Homomorphic, 33 bytes: `43ae4f1e3b6f1dcdd636bb3f6371432b2549ad11381d8c9a5c7d121d9fbb4db8`

The `scale/` and `comparative/` directories are the unmodified GitHub Actions artifacts. `fuzz/` contains the raw crash corpus files, and `ct/` contains the source/functional report.
