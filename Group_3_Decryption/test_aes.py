import unittest

if __package__:
    from . import aes_decrypt as aes
else:
    import aes_decrypt as aes


def state_from_hex(block_hex):
    block = bytes.fromhex(block_hex)
    return [list(block[row::4]) for row in range(4)]


class TestAES128(unittest.TestCase):
    # FIPS 197 (2001), Appendix C.1.
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_inverse_sbox(self):
        recovered = bytes(aes.INV_SBOX[value] for value in aes.SBOX)
        self.assertEqual(recovered, bytes(range(256)))
        state = state_from_hex("637c777bf26b6fc53001672bfed7ab76")
        self.assertIs(aes.inv_sub_bytes(state), state)
        self.assertEqual(state, state_from_hex(self.KEY.hex()))

    def test_inverse_sub_bytes_accepts_custom_table(self):
        state = [[0xFF] * 4 for _ in range(4)]
        custom_table = list(range(1, 256)) + [0]
        self.assertIs(aes.inv_sub_bytes(state, custom_table), state)
        self.assertEqual(state, [[0] * 4 for _ in range(4)])

    def test_inverse_shift_rows(self):
        state = [
            [0x00, 0x01, 0x02, 0x03],
            [0x10, 0x11, 0x12, 0x13],
            [0x20, 0x21, 0x22, 0x23],
            [0x30, 0x31, 0x32, 0x33],
        ]
        self.assertIs(aes.inv_shift_rows(state), state)
        self.assertEqual(state, [
            [0x00, 0x01, 0x02, 0x03],
            [0x13, 0x10, 0x11, 0x12],
            [0x22, 0x23, 0x20, 0x21],
            [0x31, 0x32, 0x33, 0x30],
        ])

    def test_inverse_mix_columns(self):
        state = state_from_hex("1741a11891c991688c36386f23ad82aa")
        self.assertIs(aes.inv_mix_columns(state), state)
        self.assertEqual(state, state_from_hex("8333f0afff15a6edc191b409770e815e"))

    def test_add_round_key(self):
        state = state_from_hex(self.CIPHERTEXT.hex())
        round_key = bytes.fromhex("13111d7fe3944a17f307a78b4d2b30c5")
        self.assertIs(aes.add_round_key(state, round_key), state)
        self.assertEqual(state, state_from_hex("7ad5fda789ef4e272bca100b3d9ff59f"))

    def test_key_expansion(self):
        expected_keys = [
            "000102030405060708090a0b0c0d0e0f",
            "d6aa74fdd2af72fadaa678f1d6ab76fe",
            "b692cf0b643dbdf1be9bc5006830b3fe",
            "b6ff744ed2c2c9bf6c590cbf0469bf41",
            "47f7f7bc95353e03f96c32bcfd058dfd",
            "3caaa3e8a99f9deb50f3af57adf622aa",
            "5e390f7df7a69296a7553dc10aa31f6b",
            "14f9701ae35fe28c440adf4d4ea9c026",
            "47438735a41c65b9e016baf4aebf7ad2",
            "549932d1f08557681093ed9cbe2c974e",
            "13111d7fe3944a17f307a78b4d2b30c5",
        ]
        self.assertEqual(
            aes.expand_key(self.KEY), [bytes.fromhex(key) for key in expected_keys]
        )

    def test_decrypt_fips_197_vector(self):
        self.assertEqual(aes.decrypt_block(self.CIPHERTEXT, self.KEY), self.PLAINTEXT)

    def test_decrypt_nist_sp_800_38a_vectors(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        vectors = (
            ("3ad77bb40d7a3660a89ecaf32466ef97", "6bc1bee22e409f96e93d7e117393172a"),
            ("f5d3d58503b9699de785895a96fdbaaf", "ae2d8a571e03ac9c9eb76fac45af8e51"),
            ("43b1cd7f598ece23881b00e3ed030688", "30c81c46a35ce411e5fbc1191a0a52ef"),
            ("7b0c785e27e8ad3f8223207104725dd4", "f69f2445df4f9b17ad2b417be66c3710"),
        )
        for ciphertext, plaintext in vectors:
            with self.subTest(ciphertext=ciphertext):
                self.assertEqual(
                    aes.decrypt_block(bytes.fromhex(ciphertext), key), bytes.fromhex(plaintext)
                )

    def test_bytes_like_inputs(self):
        ciphertext = bytearray(self.CIPHERTEXT)
        key = bytearray(self.KEY)
        plaintext = aes.decrypt_block(ciphertext, memoryview(key))
        self.assertIsInstance(plaintext, bytes)
        self.assertEqual(plaintext, self.PLAINTEXT)
        self.assertEqual(ciphertext, self.CIPHERTEXT)
        self.assertEqual(key, self.KEY)

    def test_invalid_lengths(self):
        for size in (0, 15, 17, 24, 32):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, "ciphertext must be exactly 16 bytes"):
                    aes.decrypt_block(bytes(size), self.KEY)
                with self.assertRaisesRegex(ValueError, "key must be exactly 16 bytes"):
                    aes.decrypt_block(self.CIPHERTEXT, bytes(size))

    def test_invalid_types(self):
        with self.assertRaisesRegex(TypeError, "ciphertext must be a bytes-like object"):
            aes.decrypt_block(self.CIPHERTEXT.hex(), self.KEY)
        with self.assertRaisesRegex(TypeError, "key must be a bytes-like object"):
            aes.decrypt_block(self.CIPHERTEXT, 16)


if __name__ == "__main__":
    unittest.main()
