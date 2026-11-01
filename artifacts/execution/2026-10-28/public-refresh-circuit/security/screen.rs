#[path="/workspace/NINE65_v7/crates/nine65/src/params/security_estimator.rs"]
mod security_estimator;
use security_estimator::{LatticeSecurityEstimator, SecretDistribution, ScreenVerdict};
fn main() {
    let main = [998244353,985661441,754974721,469762049,576460752301785089,576460752301391873,576460752300015617,576460752298835969,576460752298180609,576460752293134337,576460752291954689,576460752290775041,575870995836829697];
    let factors:Vec<_> = main.iter().map(|&p|(p,1)).collect();
    let result=LatticeSecurityEstimator::default().dual_estimate_with_factorization(32768,&factors,SecretDistribution::Ternary,128);
    for (name, value) in [("CoreSVP",&result.core_svp),("MATZOV",&result.matzov)] {
        match &value.verdict {
            ScreenVerdict::Screened(v) => println!("{{\"model\":\"{}\",\"screened\":true,\"n\":32768,\"q_bits\":{},\"lanes\":{},\"widest_lane_bits\":{},\"classical_bits\":{},\"hybrid_bits\":{},\"quantum_heuristic_bits\":{},\"effective_bits\":{},\"meets_128_classical_hybrid\":{},\"bkz_block_size\":{}}}",name,value.total_log_q,value.distinct_lane_count,value.widest_lane_bits,v.classical_bits,v.hybrid_bits,v.quantum_bits,v.effective_bits,v.meets_claim,v.bkz_block_size),
            ScreenVerdict::Refused(v) => panic!("unexpected structural refusal: {:?}",v),
        }
    }
    assert_eq!(result.binding_bits,Some(129));
    assert!(result.meets_both);
}
