"""Deterministic phase-error ledger for the fixed N16/p97 attachment.

Bounds are relative to exact Delta=Q/t encoding, in phase-error units.
This model requires ternary keys, error coefficients <=8, canonical gadget
digits and the actual centered-tensor scaling of the archived implementation.
"""
from check_toy_refresh_preflight import residual_radius

N, P, ETA = 16, 97, 8
QIN, QOUT = P * 2**40, P*P * 2**900


def ceil_div(a, b):
    return (a+b-1)//b


def switching(q, bits):
    return N * ETA * ((1 << bits)-1) * ceil_div(q.bit_length(), bits)


def multiply(q, t, a, b, switch):
    if min(a,b) < 0 or 2*t*max(a,b) >= q:
        raise ValueError('input decoding headroom exhausted')
    # Full polynomial plaintext norms and centered tensor windings.
    factor=N*(t//2)+N*t*(N//2+1)
    bound=(a+b)*factor+ceil_div(N*t*a*b,q)
    bound+=ceil_div(1+N+N*N,2)+switch
    if 2*t*bound >= q:
        raise ValueError('product decoding headroom exhausted')
    return bound


def plan():
    t=P*P
    outer_switch=switching(QOUT,32)
    diagonal_norm=N*(t//2)
    def transform(error):
        return N*(error+outer_switch)*diagonal_norm
    # BK encryption, public a1 multiplication, C2S. a0 adds no error.
    clock=transform(ETA*N*(t-1))
    acc=0
    horner=[]
    for _ in range(13):
        acc=multiply(QOUT,t,acc,clock,outer_switch)
        horner.append(acc)
    restored=transform(clock+acc)
    if 2*t*restored >= QOUT:
        raise ValueError('inverse transform decoding headroom exhausted')
    # Reinterpret exact p-multiple at t=p, then component modulus switch.
    # Charge all 16 possible outer-secret terms, plus c0's rounding.
    dropped=ceil_div(2*restored*QIN+17*QOUT,2*QOUT)
    returned=dropped+switching(QIN,8)
    following=multiply(QIN,P,returned,returned,switching(QIN,8))
    radius=residual_radius(QIN,P,4,following)
    if radius>3:
        raise ValueError('following square cannot reenter radius-3 refresh')
    return dict(clock_error=clock,horner_errors=horner,restored_error=restored,
                dropped_error=dropped,returned_error=returned,
                following_square_error=following,next_residual_radius=radius)


if __name__=='__main__':
    import json
    print(json.dumps(plan(),indent=2))
