# PR #167 hosted artifacts for `0f85873`

This head contains no source or workflow changes after `57af1de`; it adds the
plan checkpoint and artifact evidence. PR #167 was later merged at
`25e19eeffc82ef3a84d77d76c50e5fc9eb9a026f`.

* [CI run 37673287983](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37673287983): T1 Fast Gate, static analysis, and T3 pass. T2 Full Test Suite was still running when recorded.
* [CT run 37673287889](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37673287889): source/functional gate passes; blocking dudect fails. `mod_switch_down_dual` all-zero vs uniform has `t_control=0.8098`, `t_signal=49.4668` against threshold 5, with medians 64,466,796 ns and 66,017,183 ns.
* [Fuzz Smoke run 37673287941](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37673287941): deserialize, encrypt/decrypt, and homomorphic targets fail; NTT and K-Elimination pass. The raw corpora and job log are retained under `fuzz/`.
* [CRAM-public run 37673287919](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37673287919): correctness and informational timings pass.
* Application platform run 37673287908, exploratory matrix run 37673287871, scale run 37673288033, and comparative run 37673287881 pass. The scale and comparative artifacts are retained under `pr167-57af1de/`, which ran the same source head.

Raw artifact SHA-256 values:

* Dudect output: `7e54ed72e50b29c697d40889c3a510161c760efdeaecc5d340f24c0aae1a5d49`
* Fuzz job log: `0c41745155226db56b504c6876eabd9dc28d39bf592a6d50808e785aaf6fb069`
* Deserialize input (8 bytes): `95483f25bd69e1839aa5b332c4e5cbbd230de06ce740050635ea16b18495a97b`
* Encrypt/decrypt input (17 bytes): `f901877b85776bf2c368156a621968bfdeb251cfbaa9cbf26384aca41e55801c`
* Homomorphic input (32 bytes): `be64476d2a0ac8695cb2d710050c12486e29eb4fa050663194992ceb6a5661c1`
