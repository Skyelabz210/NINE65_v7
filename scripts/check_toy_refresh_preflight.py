"""Exact residual preflight for the archived attachment's initial input.

This is not a ciphertext-history issuer or admission for subsequent squares.
The error bound comes from the fixed encryptor (8) plus its public injection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def residual_radius(q, p, support, error):
    if q <= 0 or p <= 0 or support < 0 or error < 0:
        raise ValueError('positive moduli and nonnegative support/error required')
    return (2*p*p*error + q*(support+1)) // (2*q)


def admitted(q, p, support, error, radius):
    return radius >= 0 and residual_radius(q,p,support,error) <= radius


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--seed', type=int, default=0)
    args=parser.parse_args()
    evidence=Path(__file__).resolve().parents[1]/'docs/execution/2026-11-01/toy-refresh-evidence'
    # Bind the constant-derived preflight to the exact supplied program.
    expected='1ad0f75496538f7a7b713cd493dba3765bedbc197db3a5a91a6c8b7927f0d2a5'
    if hashlib.sha256((evidence/'original.rs').read_bytes()).hexdigest()!=expected:
        parser.error('attachment changed; derive a new producer error bound')
    q,p=97*2**40,97
    error=2**40//(4*p)+8
    radius=residual_radius(q,p,4,error)
    if not admitted(q,p,4,error,3):
        parser.error('initial input exceeds the residual corridor')
    print(json.dumps({'source_error_bound':error,'residual_radius':radius,
                      'declared_radius':3,'initial_input_admitted':True}),flush=True)
    if args.run:
        subprocess.run(['cargo','run','--locked','--release','--manifest-path',
                        str(evidence/'Cargo.toml'),'--bin','original','--',str(args.seed)],check=True)


if __name__=='__main__':
    main()
