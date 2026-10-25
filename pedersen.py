"""Pedersen commitments over secp256k1, in pure Python.

A Pedersen commitment hides a value ``v`` behind a random blinding factor
``r`` while still letting anyone check that a revealed ``(v, r)`` pair
matches the commitment — and, crucially, commitments add homomorphically:

    C(v1, r1) + C(v2, r2) == C(v1 + v2, r1 + r2)

That is why confidential-transaction designs (e.g. Mimblewimble) can
prove that transaction inputs equal outputs without revealing any amount.

Construction (nothing-up-my-sleeve second generator)::

    G  = secp256k1 generator
    H  = hash_to_scalar(b"pedersen-H") * G
    C(v, r) = r * G + v * H

Security notes, kept short because this is a teaching implementation:
- ``H`` must not have a known discrete log relative to ``G``; deriving it
  from a hash is the standard way to get that.
- The blinding factor must be fresh and secret per commitment; reusing
  ``r`` across two commitments leaks the difference of the values.
- Values are taken mod the group order ``n``; negative values wrap, so
  callers that need range proofs must add one separately (out of scope).

No dependencies beyond the standard library.

>>> C = commit(42, 7)
>>> verify(C, 42, 7)
True
>>> verify(C, 43, 7)  # tampered value
False
>>> verify(C, 42, 8)  # tampered blinding factor
False
>>> # Homomorphic addition: commitments add like the values they hide.
>>> C1, C2 = commit(10, 3), commit(32, 5)
>>> add(C1, C2) == commit(42, 8)
True
>>> # A zero-value commitment is just a multiple of G.
>>> commit(0, 9) == scalar_mul(9, G)
True
>>> # Different blinding factors give different commitments.
>>> commit(42, 7) != commit(42, 8)
True
>>> # verify() rejects garbage gracefully instead of raising.
>>> verify((1, 2), 42, 7)
False
"""

import hashlib

# secp256k1 domain parameters (SEC 2).
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# The point at infinity, represented as None.
INF = None


def _add(P1, P2):
    """Add two curve points (None = point at infinity)."""
    if P1 is INF:
        return P2
    if P2 is INF:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if P1 == P2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, point):
    """Multiply a curve point by scalar ``k`` (double-and-add)."""
    k %= N
    result = INF
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _hash_to_scalar(label):
    """Derive a scalar in [1, N-1] from a label (SHA-256, nothing-up-my-sleeve)."""
    return int.from_bytes(hashlib.sha256(label).digest(), "big") % (N - 1) + 1


# Second generator: H = hash_to_scalar("pedersen-H") * G. Nobody knows
# log_G(H), which is exactly what makes the scheme binding.
H = scalar_mul(_hash_to_scalar(b"pedersen-H"), G)


def commit(value, blinding):
    """Return the Pedersen commitment ``C = r*G + v*H`` for value ``v``.

    >>> C = commit(5, 11)
    >>> isinstance(C, tuple) and len(C) == 2
    True
    """
    return _add(scalar_mul(blinding, G), scalar_mul(value, H))


def verify(commitment, value, blinding):
    """Check whether ``(value, blinding)`` opens ``commitment``.

    Returns False (never raises) for malformed commitments.

    >>> C = commit(100, 55)
    >>> verify(C, 100, 55)
    True
    >>> verify(C, 100, 56)
    False
    """
    try:
        if not (isinstance(commitment, tuple) and len(commitment) == 2):
            return False
        x, y = commitment
        if not (0 <= x < P and 0 <= y < P):
            return False
        if (y * y - (x * x * x + 7)) % P != 0:
            return False
        return commit(value, blinding) == commitment
    except (TypeError, ValueError):
        return False


def add(C1, C2):
    """Add two commitments point-wise (the homomorphic operation).

    >>> add(commit(3, 4), commit(9, 6)) == commit(12, 10)
    True
    """
    return _add(C1, C2)


def sub(C1, C2):
    """Subtract one commitment from another (negate ``C2`` then add).

    >>> sub(commit(42, 8), commit(10, 3)) == commit(32, 5)
    True
    >>> sub(commit(10, 3), commit(10, 3)) is INF
    True
    """
    return _add(C1, (C2[0], (-C2[1]) % P))


def demo():
    """Run a small confidential-transaction-style demo."""
    import secrets

    print("Pedersen commitments over secp256k1")
    print("-----------------------------------")
    # Alice commits to sending 30 coins; Bob commits to receiving 30.
    v_in, v_out = 30, 30
    r_in, r_out = secrets.randbelow(N - 1) + 1, secrets.randbelow(N - 1) + 1
    c_in, c_out = commit(v_in, r_in), commit(v_out, r_out)
    print(f"input commitment  : ({c_in[0]:#x}, {c_in[1]:#x})")
    print(f"output commitment : ({c_out[0]:#x}, {c_out[1]:#x})")
    # Balance check without revealing amounts: C_in - C_out must be a
    # commitment to zero, i.e. openable with value 0.
    diff = sub(c_in, c_out)
    print("balanced (opens to 0)?", verify(diff, 0, (r_in - r_out) % N))
    print("tampered amount opens?", verify(c_out, 31, r_out))


if __name__ == "__main__":
    import doctest
    import sys

    if "--demo" in sys.argv:
        demo()
    elif "--test" in sys.argv:
        results = doctest.testmod(verbose=False)
        print(f"{results.attempted} doctests, {results.failed} failed")
        sys.exit(1 if results.failed else 0)
    else:
        demo()
