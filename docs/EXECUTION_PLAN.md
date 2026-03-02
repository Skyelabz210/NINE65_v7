# NINE65 v7 Proof Audit - Execution Plan

**Generated:** March 2, 2026  
**Strategy:** Parallel Subagent Execution with Dependency Resolution  

---

## Task Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 1: IMMEDIATE (Week 1)                          │
│                     [No Prerequisites - All Parallel]                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Task 1.1:        │  │ Task 1.2:        │  │ Task 1.3:        │          │
│  │ Run Statistical  │  │ Run Verification │  │ Analyze Test     │          │
│  │ Timing Tests     │  │ Script           │  │ Results          │          │
│  │                  │  │                  │  │                  │          │
│  │ Agent: test-runner│ │ Agent: scanner   │  │ Agent: analyst   │          │
│  └─────────┬────────┘  └─────────┬────────┘  └─────────┬────────┘          │
│            │                     │                     │                    │
│            └─────────────────────┼─────────────────────┘                    │
│                                  │                                          │
│                          ┌───────▼───────┐                                  │
│                          │ Task 1.4:     │                                  │
│                          │ Generate      │                                  │
│                          │ Phase 1 Report│                                  │
│                          └───────┬───────┘                                  │
│                                  │                                          │
└──────────────────────────────────┼──────────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────────┐
│                        PHASE 2: SHORT-TERM (Weeks 2-4)                      │
│                     [Depends on Phase 1 Completion]                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ Task 2.1: Complete MontgomeryContext.v Proofs                   │        │
│  │ [8 theorems - Can be parallelized per theorem]                  │        │
│  ├─────────────────────────────────────────────────────────────────┤        │
│  │                                                                 │        │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │        │
│  │  │ 2.1.1       │ │ 2.1.2       │ │ 2.1.3       │ │ 2.1.4     │ │        │
│  │  │ redc_m_     │ │ redc_       │ │ redc_       │ │ mont_     │ │        │
│  │  │ property    │ │ divisibility│ │ correct     │ │ mul_correct││        │
│  │  │ [coq-expert]│ │ [coq-expert]│ │ [coq-expert]│ │ [coq-expert]││       │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │        │
│  │                                                                 │        │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │        │
│  │  │ 2.1.5       │ │ 2.1.6       │ │ 2.1.7       │ │ 2.1.8     │ │        │
│  │  │ mont_       │ │ mont_       │ │ mont_       │ │ mask_     │ │        │
│  │  │ add_correct │ │ sub_correct │ │ pow_correct │ │ correct   │ │        │
│  │  │ [coq-expert]│ │ [coq-expert]│ │ [coq-expert]│ │ [coq-expert]││       │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │        │
│  │                                                                 │        │
│  │  ┌─────────────────────────────────────────────────────────────┐│        │
│  │  │ Task 2.1.9: Compile and Verify All Proofs                   ││        │
│  │  │ [Depends: 2.1.1 through 2.1.8 complete]                     ││        │
│  │  └─────────────────────────────────────────────────────────────┘│        │
│  └─────────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Task 2.2:        │  │ Task 2.3:        │  │ Task 2.4:        │          │
│  │ CI Integration   │  │ Expand Test      │  │ Documentation    │          │
│  │ GitHub Actions   │  │ Coverage         │  │ Updates          │          │
│  │                  │  │                  │  │                  │          │
│  │ [ci-agent]       │  │ [test-agent]     │  │ [doc-agent]      │          │
│  └─────────┬────────┘  └─────────┬────────┘  └─────────┬────────┘          │
│            │                     │                     │                    │
│            └─────────────────────┼─────────────────────┘                    │
│                                  │                                          │
│                          ┌───────▼───────┐                                  │
│                          │ Task 2.5:     │                                  │
│                          │ Generate      │                                  │
│                          │ Phase 2 Report│                                  │
│                          └───────┬───────┘                                  │
│                                  │                                          │
└──────────────────────────────────┼──────────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────────────┐
│                        PHASE 3: LONG-TERM (Months 2-3)                      │
│                     [Depends on Phase 2 Completion]                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Task 3.1:        │  │ Task 3.2:        │  │ Task 3.3:        │          │
│  │ ct-verif Deep    │  │ timecop          │  │ Full Security    │          │
│  │ Integration      │  │ Integration      │  │ Documentation    │          │
│  │                  │  │                  │  │                  │          │
│  │ [formal-agent]   │  │ [llvm-agent]     │  │ [doc-agent]      │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Task Decomposition

### Phase 1: Immediate (No Prerequisites)

| ID | Task | Agent | Estimated Time | Parallel |
|----|------|-------|----------------|----------|
| 1.1 | Run statistical timing tests | test-runner | 10 min | ✓ |
| 1.2 | Run verification script | scanner | 5 min | ✓ |
| 1.3 | Analyze test results | analyst | 15 min | ✓ (after 1.1, 1.2) |
| 1.4 | Generate Phase 1 report | reporter | 5 min | ✗ (after 1.3) |

### Phase 2: Short-Term (Depends on Phase 1)

| ID | Task | Agent | Estimated Time | Parallel |
|----|------|-------|----------------|----------|
| 2.1.1 | Prove redc_m_property | coq-expert | 2 hours | ✓ |
| 2.1.2 | Prove redc_divisibility | coq-expert | 2 hours | ✓ |
| 2.1.3 | Prove redc_correct | coq-expert | 3 hours | ✓ |
| 2.1.4 | Prove mont_mul_correct | coq-expert | 2 hours | ✓ |
| 2.1.5 | Prove mont_add_correct | coq-expert | 1 hour | ✓ |
| 2.1.6 | Prove mont_sub_correct | coq-expert | 1 hour | ✓ |
| 2.1.7 | Prove mont_pow_correct | coq-expert | 3 hours | ✓ |
| 2.1.8 | Prove mask_correctness | coq-expert | 2 hours | ✓ |
| 2.1.9 | Compile and verify all proofs | coq-expert | 1 hour | ✗ (after 2.1.1-2.1.8) |
| 2.2 | CI Integration (GitHub Actions) | ci-agent | 4 hours | ✓ |
| 2.3 | Expand test coverage | test-agent | 6 hours | ✓ |
| 2.4 | Documentation updates | doc-agent | 3 hours | ✓ |
| 2.5 | Generate Phase 2 report | reporter | 1 hour | ✗ (after 2.1.9, 2.2, 2.3, 2.4) |

### Phase 3: Long-Term (Depends on Phase 2)

| ID | Task | Agent | Estimated Time | Parallel |
|----|------|-------|----------------|----------|
| 3.1 | ct-verif deep integration | formal-agent | 40 hours | ✓ |
| 3.2 | timecop integration | llvm-agent | 20 hours | ✓ |
| 3.3 | Full security documentation | doc-agent | 10 hours | ✓ |

---

## Execution Strategy

### Parallel Execution Groups

**Group 1 (Phase 1 - Immediate):**
- 1.1, 1.2 can run simultaneously
- 1.3 waits for 1.1, 1.2 results
- 1.4 waits for 1.3

**Group 2 (Phase 2 - Proof Completion):**
- 2.1.1 through 2.1.8 can ALL run in parallel (8 independent Coq proofs)
- 2.1.9 waits for all 2.1.x proofs
- 2.2, 2.3, 2.4 can run parallel with 2.1.x group
- 2.5 waits for 2.1.9, 2.2, 2.3, 2.4

**Group 3 (Phase 3 - Deep Integration):**
- 3.1, 3.2, 3.3 can ALL run in parallel

---

## Agent Assignments

| Agent | Specialization | Assigned Tasks |
|-------|----------------|----------------|
| `test-runner` | Cargo test execution | 1.1 |
| `scanner` | Script execution, pattern scanning | 1.2 |
| `analyst` | Result analysis, statistics | 1.3 |
| `reporter` | Report generation, documentation | 1.4, 2.5, Final |
| `coq-expert-1` | Coq proofs (REDC) | 2.1.1, 2.1.2, 2.1.3 |
| `coq-expert-2` | Coq proofs (Montgomery ops) | 2.1.4, 2.1.5, 2.1.6 |
| `coq-expert-3` | Coq proofs (Advanced) | 2.1.7, 2.1.8, 2.1.9 |
| `ci-agent` | GitHub Actions, CI/CD | 2.2 |
| `test-agent` | Test expansion | 2.3 |
| `doc-agent` | Documentation | 2.4, 3.3 |
| `formal-agent` | ct-verif integration | 3.1 |
| `llvm-agent` | timecop integration | 3.2 |

---

## Success Criteria

### Phase 1
- [ ] All statistical tests pass (CV < 1%)
- [ ] Verification script completes without FAIL
- [ ] Results documented in Phase 1 report

### Phase 2
- [ ] All 8 MontgomeryContext theorems proved (no admits)
- [ ] Coq compilation succeeds (coqc returns 0)
- [ ] CI workflow created and functional
- [ ] Test coverage expanded to 90%+ of CT functions
- [ ] SECURITY.md updated with CT status

### Phase 3
- [ ] ct-verif annotations added to all CT functions
- [ ] timecop binary analysis integrated
- [ ] Complete security documentation published

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Coq proofs too complex | High | Split into smaller lemmas, use automation |
| Statistical tests fail | High | Review CT implementations, fix timing leaks |
| CI integration blocked | Medium | Use alternative (local verification script) |
| ct-verif Rust support limited | Medium | Fall back to timecop + statistical tests |

---

## Timeline Summary

```
Week 1:  Phase 1 Complete (Immediate verification)
Week 2:  Phase 2.1 Complete (Proofs - parallel 8-way)
Week 3:  Phase 2.2-2.4 Complete (CI, Tests, Docs - parallel)
Week 4:  Phase 2.5 Complete (Phase 2 report)
Month 2: Phase 3.1-3.2 Complete (Deep integration)
Month 3: Phase 3.3 Complete (Full documentation)
```

**Total Estimated Effort:** 120-140 hours over 12 weeks

---

## Next Action

Deploy subagents for **Phase 1** execution (no prerequisites).
