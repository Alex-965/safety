import base64
import unittest
from crypto_lab import *

class ClassicalTests(unittest.TestCase):
    def test_caesar_given(self):
        self.assertEqual(caesar_bruteforce("vppanlwxlyopyncjae")[11], (11, "keepcalmandencrypt"))
        self.assertEqual(len(caesar_bruteforce("abc")), 26)

    def test_caesar_roundtrip_and_case(self):
        for k in range(26):
            self.assertEqual(caesar(caesar("Hello, Zz! 123", k), -k), "Hello, Zz! 123")

    def test_vigenere_known_vector(self):
        self.assertEqual(vigenere("аааа", "б"), "бббб")
        self.assertEqual(vigenere("я", "б"), "а")

    def test_vigenere_punctuation_case_normalization(self):
        text = "Їжак, Ґанок i КРИПТОГРАФІЯ!"
        self.assertEqual(vigenere(vigenere(text, "кобзей"), "кобзей", decrypt=True), normalize_ukrainian(text))
        self.assertEqual(vigenere("а а", "бв"), "б в")

    def test_bad_key(self):
        for key in ("", "123", "abc"):
            with self.assertRaises(ValueError): vigenere("текст", key)

    def test_primality(self):
        for n in (2, 3, 17, 97, 65537): self.assertTrue(is_probable_prime(n))
        for n in (-1, 0, 1, 4, 15, 561, 1105, 1729): self.assertFalse(is_probable_prime(n))

class RSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_rsa_key()
        cls.private = cls.key.private_key()
        cls.public = cls.private.public_key()

    def test_generated_key_relationships(self):
        self.assertNotEqual(self.key.p, self.key.q)
        self.assertEqual(self.key.n.bit_length(), 2048)
        self.assertEqual(self.key.n, self.key.p * self.key.q)
        self.assertEqual((self.key.e * self.key.d) % self.key.phi, 1)

    def test_number_100_and_boundaries(self):
        for m in (0, 1, 100, self.key.n - 1):
            self.assertEqual(rsa_decrypt_int(rsa_encrypt_int(m, self.key), self.key), m)
        for m in (-1, self.key.n):
            with self.assertRaises(ValueError): rsa_encrypt_int(m, self.key)
            with self.assertRaises(ValueError): rsa_decrypt_int(m, self.key)

    def test_utf8_empty_and_multiple_blocks(self):
        for text in ("", "Hello", "Українська ґ є і ї 🔐", "a" * 189 + "ї" + "🔐" * 500, "x" * 190, "x" * 191):
            self.assertEqual(rsa_decrypt_text(rsa_encrypt_text(text, self.public), self.private), text)

    def test_randomized_oaep(self):
        self.assertNotEqual(rsa_encrypt_text("same", self.public), rsa_encrypt_text("same", self.public))

    def test_invalid_base64_or_partial_block(self):
        for value in ("%%%", base64.b64encode(b"short").decode()):
            with self.assertRaises(ValueError): rsa_decrypt_text(value, self.private)

    def test_tampering_rejected(self):
        raw = bytearray(base64.b64decode(rsa_encrypt_text("message", self.public)))
        raw[20] ^= 1
        with self.assertRaises(ValueError):
            rsa_decrypt_text(base64.b64encode(raw).decode(), self.private)

if __name__ == "__main__": unittest.main(verbosity=2)
