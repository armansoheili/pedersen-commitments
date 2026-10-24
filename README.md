# pedersen-commitments

Pedersen commitments over secp256k1 in pure Python — zero dependencies.

A Pedersen commitment hides a value `v` behind a random blinding factor
`r`, while still letting anyone verify a revealed `(v, r)` pair — and
commitments add homomorphically:

```
C(v1, r1) + C(v2, r2) == C(v1 + v2, r1 + r2)
```

That property is what lets confidential-transaction designs (like
Mimblewimble) prove inputs equal outputs without revealing any amounts.

## Construction

```
G = secp256k1 generator
H = hash_to_scalar("pedersen-H") * G   # nothing-up-my-sleeve second generator
C(v, r) = r * G + v * H
```

## Usage

```python
from pedersen import commit, verify, add

C = commit(42, 7)
verify(C, 42, 7)          # True
verify(C, 43, 7)          # False — tampered value

# Homomorphic addition:
add(commit(10, 3), commit(32, 5)) == commit(42, 8)   # True
```

## Run

```sh
python3 pedersen.py --demo   # confidential-transaction-style demo
python3 pedersen.py --test   # run the doctests
```

## Notes

- `H` must not have a known discrete log relative to `G`; deriving it
  from a hash is the standard way to get that.
- Never reuse a blinding factor across two commitments — it leaks the
  difference of the values.
- This is a teaching implementation; range proofs (needed to stop
  negative-value tricks) are out of scope.
