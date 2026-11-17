//! Public-API checks compiled against the actual dependency-free cram-core.
use cram_core::query_runtime::{AdjacentProducer, QueryError, QuerySpec};

fn query(p: &AdjacentProducer, s: &cram_core::query_runtime::SourceState, q: QuerySpec) -> u64 {
    let o = p.observe(s).unwrap();
    o.execute(&o.plan(q).unwrap()).unwrap().residue
}

fn main() {
    let mut checks = 0usize;
    for m in [2u64,3,4,6,9,36] {
        let cap = m * (m+1);
        let p = AdjacentProducer::new(m,cap-1).unwrap();
        for x in 0..cap {
            let s = p.ingress(x).unwrap();
            for d in [1,2,3,m,m+1,cap/2,cap-1,cap,u64::MAX] {
                for b in [1,2,7,37,u64::MAX] {
                    for negate in [false,true] {
                        let expected = if negate { -(x as i128 / d as i128) } else { x as i128 / d as i128 };
                        assert_eq!(query(&p,&s,QuerySpec::FloorQuotient{divisor:d,modulus:b,negate}),
                                   expected.rem_euclid(b as i128) as u64);
                        checks += 1;
                    }
                }
            }
        }
    }
    // Word-boundary arithmetic: the oracle uses a signed i128 expression;
    // runtime instead transports directly through modular operations.
    let m = (1u64<<32)-1;
    let cap = m*(m+1);
    let p = AdjacentProducer::new(m,cap-1).unwrap();
    for x in [0,1,m-1,m,m+1,cap/2,cap-2,cap-1] {
        let s = p.ingress(x).unwrap();
        for a in [i64::MIN,-17,0,1,i64::MAX] {
            for c in [i64::MIN,-1,0,i64::MAX] {
                for b in [1,7,37,1<<63,u64::MAX] {
                    let expected = (a as i128*x as i128+c as i128).rem_euclid(b as i128) as u64;
                    assert_eq!(query(&p,&s,QuerySpec::LinearResidue{coefficient:a,offset:c,modulus:b}),expected);
                    checks += 1;
                }
            }
        }
        for d in [m,cap/2,cap-1,cap,u64::MAX] {
            assert_eq!(query(&p,&s,QuerySpec::FloorQuotient{divisor:d,modulus:37,negate:false}),(x/d)%37);
            checks += 1;
        }
    }
    // Same residues never imply same source authority.
    let p = AdjacentProducer::new(36,1).unwrap();
    let mut first = p.ingress(1).unwrap();
    let second = p.ingress(1).unwrap();
    let spec = QuerySpec::LinearResidue{coefficient:1,offset:0,modulus:37};
    let plan = p.observe(&first).unwrap().plan(spec).unwrap();
    assert_eq!(p.observe(&second).unwrap().execute(&plan),Err(QueryError::SourceMismatch));
    p.add_assign(&mut first,&p.ingress(0).unwrap()).unwrap();
    assert_eq!(p.observe(&first).unwrap().execute(&plan),Err(QueryError::StaleEpoch));
    assert_eq!(query(&p,&first,spec),1);
    let other = AdjacentProducer::new(36,1).unwrap();
    assert!(matches!(other.observe(&first),Err(QueryError::FrameMismatch)));
    // An operation can fail despite tiny actual values when its public bounds
    // cannot prove admission; the old authority remains usable on failure.
    let p = AdjacentProducer::new(36,1331).unwrap();
    let mut state = p.ingress(0).unwrap();
    let other = p.ingress(0).unwrap();
    let plan = p.observe(&state).unwrap().plan(spec).unwrap();
    assert_eq!(p.multiply_assign(&mut state,&other),Err(QueryError::CapacityExceeded));
    assert_eq!(p.observe(&state).unwrap().execute(&plan).unwrap().residue,0);
    // Public admission must use the declared bound, not the actual secret-free
    // sample value. Large worst-case work is refused even for an actual zero.
    let p = AdjacentProducer::new(2000,2_000_001).unwrap();
    let zero = p.ingress(0).unwrap();
    let o = p.observe(&zero).unwrap();
    let q = QuerySpec::FloorQuotient{divisor:1,modulus:37,negate:false};
    assert!(matches!(o.plan(q),Err(QueryError::WorkBudgetExceeded)));
    assert!(matches!(o.plan_with_budget(q,2_000_000),Err(QueryError::WorkBudgetExceeded)));
    let budgeted = o.plan_with_budget(q,2_000_001).unwrap();
    assert_eq!(budgeted.quotient_step_bound(),2_000_001);
    assert_eq!(o.execute(&budgeted).unwrap().residue,0);
    let fast = o.plan_with_budget(QuerySpec::FloorQuotient{divisor:2000,modulus:37,negate:false},0).unwrap();
    assert_eq!(fast.quotient_step_bound(),0);
    let constant = o.plan_with_budget(QuerySpec::FloorQuotient{divisor:1,modulus:1,negate:false},0).unwrap();
    assert_eq!(constant.quotient_step_bound(),0);
    assert_eq!(o.execute(&constant).unwrap().residue,0);
    println!("PASS: {checks} actual public-API query checks plus source/epoch/frame/atomic-refusal/work-budget controls");
}
