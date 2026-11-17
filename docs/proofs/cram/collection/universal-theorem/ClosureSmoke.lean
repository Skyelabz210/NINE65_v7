import ResiduePrimitives

/-!
Executable wiring checks. Ordinary numbers and encode are used here only as
test ingress and an independent oracle; the runtime algorithms receive states.
The universal correctness claims are proved in the other modules.
-/

open KElimination.ResiduePrimitives

def expect (label : String) (ok : Bool) : IO Unit :=
  unless ok do throw (IO.userError label)

def checkPair (f : Frame) (n d : Nat) : IO Unit := do
  let x := f.encode n
  let y := f.encode d
  expect s!"compare {n},{d}" (f.less x y == decide (n < d))
  expect s!"gcd {n},{d}" (f.gcd x y == some (f.encode (Nat.gcd n d)))
  if d == 0 then
    expect s!"zero refusal {n}" (f.divmod x y == none)
  else
    expect s!"divmod {n},{d}"
      (f.divmod x y == some (f.encode (n / d), f.encode (n % d)))

def main : IO Unit := do
  let small := Frame.adjacent 2 (by decide)
  let shared := Frame.adjacent 6 (by decide)
  let mut count := 0
  for f in [small, shared] do
    for n in List.range f.capacity do
      for d in List.range f.capacity do
        checkPair f n d
        count := count + 1
  let wide := Frame.adjacent 36 (by decide)
  for pair in [(1331, 1), (1265, 60), (1331, 37), (0, 37), (1331, 0),
               (0, 0), (1296, 36), (1331, 1331), (665, 666)] do
    checkPair wide pair.1 pair.2
    count := count + 1
  expect "exhausted division fuel returns none"
    (KElimination.ResidueAlgorithms.divLoop shared.ops 0 zero
      (shared.encode 41) (shared.encode 6) == none)
  expect "exhausted gcd fuel returns none"
    (KElimination.ResidueAlgorithms.gcdLoop shared.ops 0
      (shared.encode 30) (shared.encode 18) == none)
  expect "out-of-window alias control"
    (wide.encode (wide.capacity + 1) == wide.encode 1 &&
      wide.less (wide.encode (wide.capacity + 1)) (wide.encode 2))
  let x := wide.encode 36
  let y := wide.encode 72
  let wrongX := (x.anchor - x.main) % 37
  let wrongY := (y.anchor - y.main) % 37
  expect "reversed positive-K orientation control"
    (wide.less x y && !(decide (wrongX < wrongY)))
  IO.println s!"PASS: {count} comparison/divmod/GCD pairs; exhaustive frames 2/3 and 6/7; 9 fixtures in 36/37; 4 refusal/negative controls."

#eval main
