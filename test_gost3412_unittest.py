import importlib.util
import pathlib
import unittest


def load_cipher_module():
    module_path = pathlib.Path(__file__).parent / 'gost-34.12-2015.py'
    spec = importlib.util.spec_from_file_location('gost34122015_module', module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Gost34122015TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module = load_cipher_module()
        cls.gost34122015 = module.gost34122015
        cls.cipher = cls.gost34122015(
            bytes.fromhex('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')
        )

    def test_s_examples_from_gost(self):
        first = bytes.fromhex('ffeeddccbbaa99881122334455667700')
        second = bytes.fromhex('b66cd8887d38e8d77765aeea0c9a7efc')
        third = bytes.fromhex('559d8dd7bd06cbfe7e7b262523280d39')
        self.assertEqual(self.cipher.S(first), second)
        self.assertEqual(self.cipher.S(second), third)

    def test_r_example_from_gost(self):
        block = bytes.fromhex('00000000000000000000000000000100')
        expected = bytes.fromhex('94000000000000000000000000000001')
        self.assertEqual(self.cipher.R(block), expected)

    def test_l_example_from_gost(self):
        block = bytes.fromhex('64a59400000000000000000000000000')
        expected = bytes.fromhex('d456584dd0e3e84cc3166e4b7fa2890d')
        self.assertEqual(self.cipher.L(block), expected)
        self.assertEqual(self.cipher.L_inv(expected), block)

    def test_key_schedule_matches_gost(self):
        expected_keys = [
            '8899aabbccddeeff0011223344556677',
            'fedcba98765432100123456789abcdef',
            'db31485315694343228d6aef8cc78c44',
            '3d4553d8e9cfec6815ebadc40a9ffd04',
            '57646468c44a5e28d3e59246f429f1ac',
            'bd079435165c6432b532e82834da581b',
            '51e640757e8745de705727265a0098b1',
            '5a7925017b9fdd3ed72a91a22286f984',
            'bb44e25378c73123a5f32f73cdb6e517',
            '72e9dd7416bcf45b755dbaa88e4a4043',
        ]
        decoded = [bytes.fromhex(v) for v in expected_keys]
        self.assertEqual(self.cipher.K, decoded)

    def test_encrypt_decrypt_vectors(self):
        plaintext = bytes.fromhex('1122334455667700ffeeddccbbaa9988')
        ciphertext = bytes.fromhex('7f679d90bebc24305a468d42b9d4edcd')
        self.assertEqual(self.cipher.encrypt(plaintext), ciphertext)
        self.assertEqual(self.cipher.decrypt(ciphertext), plaintext)


if __name__ == '__main__':
    unittest.main()
