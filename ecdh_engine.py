import secrets
from typing import Optional, Tuple

# Curve parameters (secp256k1 domain parameters used in Bitcoin & TLS)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Point = Optional[Tuple[int, int]]


def mod_inverse(k: int, p: int) -> int:
    """Compute modular multiplicative inverse using Extended Euclidean Algorithm."""
    if k == 0:
        raise ZeroDivisionError("Division by zero in finite field")
    return pow(k, -1, p)


def point_add(p1: Point, p2: Point) -> Point:
    """Perform elliptic curve group addition P1 + P2 over GF(p)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    # Point at infinity (P + (-P) = O)
    if x1 == x2 and y1 != y2:
        return None

    # Point doubling vs distinct point addition slope (lambda)
    if x1 == x2:
        lam = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        lam = (y2 - y1) * mod_inverse(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_multiply(k: int, point: Point) -> Point:
    """Constant-pattern double-and-add scalar multiplication k * G."""
    result: Point = None
    addend: Point = point

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def generate_keypair() -> Tuple[int, Point]:
    """Generate a CSPRNG private scalar and corresponding public curve point."""
    private_key = secrets.randbelow(N - 1) + 1
    public_key = scalar_multiply(private_key, (Gx, Gy))
    return private_key, public_key


if __name__ == "__main__":
    G = (Gx, Gy)

    # Alice & Bob generate ephemeral asymmetric keypairs
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    # Derive shared secret independently over an insecure channel
    alice_shared = scalar_multiply(alice_priv, bob_pub)
    bob_shared = scalar_multiply(bob_priv, alice_pub)

    assert alice_shared == bob_shared, "Key exchange verification failed!"
    print(f"[+] Shared Secret X-Coordinate (256-bit):\n    {hex(alice_shared[0])}")
