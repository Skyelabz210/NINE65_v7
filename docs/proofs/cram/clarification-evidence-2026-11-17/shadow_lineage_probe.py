#!/usr/bin/env python3
"""Finite integer oracle checks; this is not CRAM production code or a Lean proof.

The observer retains shadow readings only. Absolute initial winding is an explicit
query input, not an updated stored winding field. The test oracle computes full
integers independently to establish what each reading should mean.
"""
import json
from pathlib import Path
from math import gcd


def delta_readout(old_shadow, new_shadow, main, lower=0):
    """Unique delta in [lower,lower+11), from authentic successor readings."""
    q = ((new_shadow - old_shadow) * pow(main, -1, 11)) % 11
    return lower + ((q - lower) % 11)


class ObservationStream:
    def __init__(self, first_shadow):
        self.readings = [first_shadow]

    def append(self, shadow):
        self.readings.append(shadow)

    def query_deltas(self, main, lower=0):
        return tuple(delta_readout(a, b, main, lower)
                     for a, b in zip(self.readings, self.readings[1:]))

    def query_winding(self, main, initial_winding, lower=0):
        return initial_winding + sum(self.query_deltas(main, lower))


def run():
    result = {'status': 'PASS', 'scope': 'finite exact-integer oracle checks; not Lean or Rust refinement', 'checks': {}}
    count = 0
    for main in [2730, 881790]:
        for remainder in [0, 1, 17, main-1]:
            for winding in [-10**100, -12, -1, 0, 1, 12, 10**100]:
                source = remainder + main*winding
                for lower in [-23, -5, 0, 10]:
                    for delta in range(lower, lower+11):
                        target = source + main*delta
                        assert source % main == target % main
                        assert delta_readout(source % 11, target % 11, main, lower) == delta
                        count += 1
    result['checks']['local_increment_signed_and_huge_absolute_winding'] = count

    traces = 0
    transitions = 0
    for main in [2730, 881790]:
        for initial in [-10**100, 0, 10**100]:
            for lower in [-5, 0]:
                # The array below is an independent full-integer test oracle.
                deltas = [lower + (7*i) % 11 for i in range(53)]
                oracle_source = 17 + main*initial
                stream = ObservationStream(oracle_source % 11)
                for delta in deltas:
                    oracle_source += main*delta
                    stream.append(oracle_source % 11)
                    transitions += 1
                assert stream.query_deltas(main, lower) == tuple(deltas)
                assert stream.query_winding(main, initial, lower) == (oracle_source-17)//main
                assert set(vars(stream)) == {'readings'}
                traces += 1
    result['checks']['retained_shadow_streams'] = traces
    result['checks']['retained_shadow_stream_transitions'] = transitions

    alias_count = 0
    for main in [2730, 881790]:
        for source in [0, 17, 17 + main*10**100, 17-main*10**100]:
            for delta in range(11):
                target1 = source + main*delta
                target2 = source + main*(delta+11)
                assert target1 % main == target2 % main
                assert target1 % 11 == target2 % 11
                # The delta+11 case is OUTSIDE the admitted [0,11) interval.
                assert delta_readout(source%11, target2%11, main) == delta != delta+11
                alias_count += 1
    result['checks']['omitted_increment_bound_negative_controls'] = alias_count

    profiles = []
    for total in [30030, 9699690]:
        main = total//11
        assert gcd(main, 11) == 1 and gcd(main, 22) == 2
        joint_main = total//22
        assert gcd(joint_main, 22) == 1
        profiles.append({'total': total, 'shadow_main': main, 'shadow_inverse': pow(main,-1,11),
                         'even_payload_joint_raw_resolution': 22//gcd(main,22),
                         'joint_main': joint_main, 'joint_inverse': pow(joint_main,-1,22)})
        for x in range(22):
            combined = x%11 + 11*((x%2-x%11)%2)
            assert combined == x
    result['profiles'] = profiles
    result['checks']['joint_raw_residue_combinations'] = 44

    main=2730
    r=17
    # Same final snapshot, two possible absolute initial coordinates.
    k1=3
    k2=k1+11
    assert ((r+main*k1)%main,(r+main*k1)%11)==((r+main*k2)%main,(r+main*k2)%11)
    result['negative_control_snapshot']={'main':main,'remainder':r,'windings':[k1,k2],'same_readings':[r,(r+main*k1)%11]}
    result['observer_storage'] = 'Only an ordered list of shadow observations; main/lower/known initial winding are supplied to queries. Query temporaries and independent oracle integers are allowed.'

    padic = 0
    for main, prime in [(2730,11), (881790,11), (36,37)]:
        for source in [-10**100, -main-1, -1, 0, 1, main+1, 10**100]:
            remainder = source % main
            quotient = source // main
            previous = None
            for depth in range(1,11):
                modulus = prime**depth
                anchor = source % modulus
                observed = ((anchor-remainder)*pow(main,-1,modulus)) % modulus
                assert observed == quotient % modulus
                if previous is not None:
                    assert observed % (prime**(depth-1)) == previous
                if main == 36:
                    geometric = sum(37**j for j in range(depth))
                    assert pow(36,-1,modulus) == (-geometric) % modulus
                    assert observed == ((remainder-anchor)*geometric) % modulus
                previous = observed
                padic += 1
    result['checks']['padic_integer_source_prefixes'] = padic

    # A coherent p-adic quotient need not itself be an ordinary integer.
    # This digit family is K=1+11+11^2+...=-1/10 in Z_11.
    previous = None
    for depth in range(1,13):
        modulus = 11**depth
        quotient = sum(11**j for j in range(depth))
        anchor = (17 + 2730*quotient) % modulus
        observed = ((anchor-17)*pow(2730,-1,modulus)) % modulus
        assert observed == quotient and (10*observed+1) % modulus == 0
        if previous is not None: assert observed % (11**(depth-1)) == previous
        previous = observed
    result['checks']['noninteger_padic_compatible_prefixes'] = 12

    # Equal finite prefixes separate when genuinely new precision is provided.
    source = 123
    depth = 5
    other = source + 2730*11**depth
    assert source%2730 == other%2730
    for j in range(1,depth+1): assert source%(11**j) == other%(11**j)
    assert source%(11**(depth+1)) != other%(11**(depth+1))
    result['checks']['finite_prefix_extension_control'] = 1
    result['adjacent_higher_precision_example'] = {
        'M':36,'anchor':37**2,'X':10000,'r':10000%36,
        'true_quotient':10000//36,
        'uncorrected_subtraction':((10000%36)-(10000%(37**2)))%(37**2),
        'compatible_readout':(((10000%36)-(10000%(37**2)))*(1+37))%(37**2)}
    assert result['adjacent_higher_precision_example']['uncorrected_subtraction'] != result['adjacent_higher_precision_example']['true_quotient']
    assert result['adjacent_higher_precision_example']['compatible_readout'] == result['adjacent_higher_precision_example']['true_quotient']
    return result


if __name__ == '__main__':
    result=run()
    target=Path(__file__).with_name('shadow_lineage_probe_results.json')
    target.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
