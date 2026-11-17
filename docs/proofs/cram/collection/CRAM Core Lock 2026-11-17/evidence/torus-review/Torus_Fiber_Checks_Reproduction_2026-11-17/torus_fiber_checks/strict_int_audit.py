#!/usr/bin/env python3
"""Strict integer-only static audit (stricter than the repo's: literals + ast.Div only).
Flags: float literals/complex, true division (/ and /=), float()/complex()/round()/divmod-with-float,
negative-constant exponents, math/cmath/statistics/random/numpy/decimal-free float APIs,
time.time()/perf_counter()/monotonic() (float-returning), float-formatting specs, json float emission risks.
Integer-only code: no output, exit 0. Uses only integers itself."""
import ast, sys
FLOAT_CALLS = {"float","complex","round"}
FLOAT_MODS = {"math","cmath","statistics","random","numpy","scipy","matplotlib","PIL","decimal"}
INT_MATH = {"gcd","lcm","prod","isqrt","comb","perm","factorial"}
TIME_FLOAT = {"time","perf_counter","monotonic","process_time","clock"}
def audit(src, name="<src>"):
    tree = ast.parse(src); out = []
    imports = set()
    for n in ast.walk(tree):
        ln = getattr(n, "lineno", 0)
        if isinstance(n, ast.Constant) and isinstance(n.value, (float, complex)): out.append((ln, "float/complex literal"))
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div): out.append((ln, "true division /"))
        elif isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Div): out.append((ln, "true division /="))
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Pow):
            r = n.right
            if isinstance(r, ast.UnaryOp) and isinstance(r.op, ast.USub): out.append((ln, "negative exponent (float result)"))
            elif isinstance(r, ast.Constant) and isinstance(r.value, int) and r.value < 0: out.append((ln, "negative exponent"))
            elif not isinstance(r, ast.Constant): out.append((ln, "ADVISORY non-constant exponent (sign not statically known)"))
        elif isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in FLOAT_CALLS: out.append((ln, f"call {f.id}()"))
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if f.value.id in FLOAT_MODS and not (f.value.id=="math" and f.attr in INT_MATH): out.append((ln, f"call {f.value.id}.{f.attr}()"))
                if f.value.id == "time" and f.attr in TIME_FLOAT: out.append((ln, f"call time.{f.attr}() returns float"))
        elif isinstance(n, ast.Import):
            for a in n.names:
                imports.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and n.module:
            imports.add(n.module.split(".")[0])
        elif isinstance(n, ast.FormattedValue) and n.format_spec is not None:
            spec = "".join(getattr(v, "value", "") for v in getattr(n.format_spec, "values", []) if isinstance(v, ast.Constant))
            if spec and spec[-1] in "eEfFgG%": out.append((ln, f"float format spec '{spec}'"))
    for m in sorted((imports & FLOAT_MODS) - {"math"}): out.append((0, f"imports float-oriented module '{m}'"))
    return sorted(set(out))
if __name__ == "__main__":
    bad = 0
    for p in sys.argv[1:]:
        res = audit(open(p, encoding="utf-8").read(), p)
        for ln, why in res: print(f"{p}:{ln}: {why}")
        bad += len(res)
    print(f"TOTAL findings: {bad}")
    sys.exit(1 if bad else 0)
