"""Kuznechik (GOST R 34.12-2015) cipher implementation."""

from consts import C, PI, PI_INV


class gost34122015:
    """Implementation of the Kuznechik (GOST R 34.12-2015) block cipher.

    @cvar T: Coefficients used in the linear feedback of transformation L.
    @cvar P: Irreducible polynomial for GF(2^8) arithmetic.
    """

    T = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
    P = 0b111000011

    def __init__(self, key: bytes):
        """Generate round keys from the 256-bit master key.

        @param key: 32-byte master key.
        @type key: L{bytes}
        @raise ValueError: If key length is not 32 bytes.
        """
        if len(key) != 32:
            raise ValueError('Incorrect key length, expected 32 bytes')

        self.K = [b''] * 10
        self.K[0] = key[:16]
        self.K[1] = key[16:]

        for i in range(1, 5):
            a1, a0 = self.K[2 * i - 2], self.K[2 * i - 1]
            for j in range(8):
                c = bytes(C[8 * (i - 1) + j])
                a1, a0 = self.F(a1, a0, c)
            self.K[2 * i], self.K[2 * i + 1] = a1, a0

    def encrypt(self, block: bytes) -> bytes:
        """Encrypt one 128-bit block.

        @param block: Plaintext block to encrypt.
        @type block: L{bytes}
        @return: Encrypted 16-byte block.
        @rtype: L{bytes}
        @raise ValueError: If block length is not 16 bytes.
        """
        if len(block) != 16:
            raise ValueError('Incorrect block length, expected 16 bytes')

        state = block
        for i in range(9):
            state = self.bxor(self.K[i], state)
            state = self.S(state)
            state = self.L(state)
        return self.bxor(state, self.K[9])

    def decrypt(self, block: bytes) -> bytes:
        """Decrypt one 128-bit block.

        @param block: Ciphertext block to decrypt.
        @type block: L{bytes}
        @return: Decrypted 16-byte block.
        @rtype: L{bytes}
        @raise ValueError: If block length is not 16 bytes.
        """
        if len(block) != 16:
            raise ValueError('Incorrect block length, expected 16 bytes')

        state = block
        for i in range(9, 0, -1):
            state = self.bxor(self.K[i], state)
            state = self.L_inv(state)
            state = self.S_inv(state)
        return self.bxor(state, self.K[0])

    def poly_mul_gf2(self, a: int, b: int) -> int:
        """Carry-less multiply of two polynomials in GF(2).

        @param a: Multiplicand polynomial.
        @param b: Multiplier polynomial.
        @type a: L{int}
        @type b: L{int}
        @return: Product polynomial before reduction.
        @rtype: L{int}
        """
        res = 0
        while a:
            if a & 1:
                res ^= b
            b <<= 1
            a >>= 1
        return res

    def poly_modP_gf2(self, a: int) -> int:
        """Reduce polynomial modulo x^8 + x^7 + x^6 + x + 1.

        @param a: Polynomial to reduce.
        @type a: L{int}
        @return: Reduced polynomial.
        @rtype: L{int}
        """
        if a == 0:
            return 0

        def deg(x: int) -> int:
            return x.bit_length() - 1

        d_mod = deg(self.P)
        while d_mod <= deg(a):
            shift = deg(a) - d_mod
            a ^= self.P << shift
        return a

    def gf_mul(self, a: int, b: int) -> int:
        """Multiply two field elements in GF(2^8).

        @param a: First operand.
        @param b: Second operand.
        @type a: L{int}
        @type b: L{int}
        @return: Product reduced by modulus P.
        @rtype: L{int}
        """
        return self.poly_modP_gf2(self.poly_mul_gf2(a, b))

    def linear(self, a: bytes) -> int:
        """Linear part used inside the R transformation.

        @param a: 16-byte state vector.
        @type a: L{bytes}
        @return: One-byte linear combination.
        @rtype: L{int}
        """
        res = 0
        for byte, coeff in zip(a, self.T):
            res ^= self.gf_mul(byte, coeff)
        return res

    def bxor(self, a: bytes, b: bytes) -> bytes:
        """Xor of two 128-bit vectors.

        @param a: First operand.
        @param b: Second operand.
        @return: Byte-wise XOR result.
        @rtype: L{bytes}
        """
        return bytes(x ^ y for x, y in zip(a, b))

    def S(self, a: bytes) -> bytes:
        """Byte-wise substitution (π).

        @param a: State to substitute.
        @type a: L{bytes}
        @return: Substituted bytes.
        @rtype: L{bytes}
        """
        return bytes(PI[b] for b in a)

    def S_inv(self, a: bytes) -> bytes:
        """Inverse substitution (π^-1).

        @param a: State to reverse-substitute.
        @type a: L{bytes}
        @return: Bytes after applying inverse substitution.
        @rtype: L{bytes}
        """
        return bytes(PI_INV[b] for b in a)

    def R(self, a: bytes) -> bytes:
        """Shift-with-mix transformation R (see A.1.2 in the standard).

        @param a: State before transformation.
        @type a: L{bytes}
        @return: State after one R step.
        @rtype: L{bytes}
        """
        return bytes([self.linear(a)]) + a[:15]

    def R_inv(self, a: bytes) -> bytes:
        """Inverse of R using the last coefficient (T[15] = 1).

        @param a: State after one R step.
        @type a: L{bytes}
        @return: State before applying R.
        @rtype: L{bytes}
        """
        x = a[0]
        tail = a[1:]
        known = 0
        for byte, coeff in zip(tail, self.T[:-1]):
            known ^= self.gf_mul(byte, coeff)
        missing = x ^ known
        return tail + bytes([missing])

    def L(self, a: bytes) -> bytes:
        """Linear transformation L = R^16.

        @param a: State before transformation.
        @type a: L{bytes}
        @return: Fully transformed state.
        @rtype: L{bytes}
        """
        for _ in range(16):
            a = self.R(a)
        return a

    def L_inv(self, a: bytes) -> bytes:
        """Inverse linear transformation L^-1 = R^-16.

        @param a: State after transformation.
        @type a: L{bytes}
        @return: State recovered by reversing L.
        @rtype: L{bytes}
        """
        for _ in range(16):
            a = self.R_inv(a)
        return a

    def F(self, a1: bytes, a0: bytes, k: bytes) -> bytes:
        """Feistel-like round used in key schedule.

        @param a1: Left half of the state.
        @param a0: Right half of the state.
        @param k: Round constant.
        @type a1: L{bytes}
        @type a0: L{bytes}
        @type k: L{bytes}
        @return: Updated halves after one key-schedule round.
        @rtype: L{tuple} of L{bytes}
        """
        return self.bxor(self.L(self.S(self.bxor(k, a1))), a0), a1


if __name__ == '__main__':
    key = bytes.fromhex('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')
    message = bytes.fromhex('1122334455667700ffeeddccbbaa9988')

    cipher = gost34122015(key)
    ciphertext = cipher.encrypt(message)
    print(ciphertext.hex())

    decrypted = cipher.decrypt(ciphertext)
    print(decrypted.hex())
