"""Generate a source-bound observer harness using deterministic cycle caps."""
import argparse
import hashlib
from pathlib import Path
from toy_refresh_ledger import plan


def generate(output):
    root=Path(__file__).resolve().parents[1]
    source=root/'docs/execution/2026-11-01/toy-refresh-evidence/cycles.rs'
    # The complete archived variant is fixed, including arithmetic/key setup.
    expected='7fcf773a4a1d10fe23de42826fc6a39862f0135133d1d9b2a94481eabad0f319'
    data=source.read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected:
        raise ValueError('cycle implementation changed; review ledger derivation')
    p=plan()
    s=data.decode()
    observer='''
fn observe_bound(cx: &Ctx, secret: &Poly, ct: &Ct, message: &Poly, cap: i64) {
    let ph = phase(cx, secret, ct);
    for (value, m) in ph.iter().zip(message) {
        let error = center(&(value - &cx.delta * m), &cx.q).abs();
        assert!(error <= bi(cap), "producer envelope understated");
    }
}
'''
    s=s.replace('fn main() {',observer+'\nfn main() {')
    old='    for cycle in 0..5 {'
    new=old+f'''
    let input_cap = if cycle == 0 {{ 2833792863i64 }} else {{ {p['following_square_error']}i64 }};
    assert!(bi(2*P2)*bi(input_cap)+&qin*bi(H as i64+1) < &qin*bi(2*(B+1)));
    observe_bound(&src, &s, &ct, &expected, input_cap);
'''
    assert s.count(old)==1
    s=s.replace(old,new)
    old='    let back = dec(&src, &s, &fin);'
    assert s.count(old)==1
    s=s.replace(old,f'''    let return_cap = if std::env::args().nth(2).as_deref() == Some("understate") {{ 0 }} else {{ {p['returned_error']} }};
    observe_bound(&src, &s, &fin, &expected, return_cap);
'''+old)
    old='    println!("post-refresh square: all {N} coefficients checked");'
    s=s.replace(old,f"    observe_bound(&src, &s, &ct, &expected, {p['following_square_error']});\n"+old)
    s=s.replace('    println!("elapsed', '    println!("deterministic cycle caps verified");\n    println!("elapsed')
    output.write_text(s)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    generate(parser.parse_args().output)
