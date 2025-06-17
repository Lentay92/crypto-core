namespace CryptoCore;

public enum EllipticCurveTypes
{
    // Elliptic curve y^2 = x^3 + ax + b
    // p - prime field modulus

    // a = 0 (DEC)
    // b = 3 (DEC)
    // p = 0xfffffffffffffffffffffffffffffffffffffffeffffee37 (HEX)
    secp192k1,

    // a = 0 (DEC)
    // b = 5 (DEC)
    // p = 0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d (HEX)
    secp224k1,

    // a = 0 (DEC)
    // b = 7 (DEC)
    // p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f (HEX)
    secp256k1,

    // a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc (HEX)
    // b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef (HEX)
    // p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff (HEX)
    secp384r1
}
