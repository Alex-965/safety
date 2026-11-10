"""Лабораторна 5. Кобзей Олександр, ІПЗ-41. Python 3.10+."""
from __future__ import annotations

import base64
import binascii
import math
import secrets
import unicodedata
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

UKRAINIAN = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"


def caesar(text: str, key: int) -> str:
    """Зсув латиниці; регістр і неалфавітні символи зберігаються."""
    result = []
    for char in text:
        first = "a" if "a" <= char <= "z" else "A" if "A" <= char <= "Z" else None
        result.append(chr((ord(char) - ord(first) + key) % 26 + ord(first)) if first else char)
    return "".join(result)


def caesar_bruteforce(ciphertext: str) -> list[tuple[int, str]]:
    return [(key, caesar(ciphertext, -key)) for key in range(26)]


def normalize_ukrainian(text: str) -> str:
    """У наданому прикладі латинська i замінюється українською і."""
    return unicodedata.normalize("NFC", text).translate(str.maketrans({"i": "і", "I": "І"}))


def vigenere(text: str, key: str, *, decrypt: bool = False) -> str:
    key = normalize_ukrainian(key).lower()
    if not key or any(c not in UKRAINIAN for c in key):
        raise ValueError("Ключ має містити тільки українські літери")
    result, index = [], 0
    for char in normalize_ukrainian(text):
        lower = char.lower()
        if lower not in UKRAINIAN:
            result.append(char)
            continue
        shift = UKRAINIAN.index(key[index % len(key)]) * (-1 if decrypt else 1)
        out = UKRAINIAN[(UKRAINIAN.index(lower) + shift) % len(UKRAINIAN)]
        result.append(out.upper() if char.isupper() else out)
        index += 1
    return "".join(result)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Міллер Рабін; випадкові незалежні основи через secrets."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("Замалий розмір простого числа")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAKey:
    p: int
    q: int
    n: int
    e: int
    d: int

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def private_key(self) -> rsa.RSAPrivateKey:
        return rsa.RSAPrivateNumbers(
            p=self.p, q=self.q, d=self.d,
            dmp1=self.d % (self.p - 1), dmq1=self.d % (self.q - 1),
            iqmp=pow(self.q, -1, self.p),
            public_numbers=rsa.RSAPublicNumbers(self.e, self.n),
        ).private_key()


def generate_rsa_key(bits: int = 2048) -> RSAKey:
    if bits < 2048 or bits % 2:
        raise ValueError("Потрібна парна довжина ключа від 2048 біт")
    e = 65537
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        n, phi = p * q, (p - 1) * (q - 1)
        if p != q and n.bit_length() == bits and math.gcd(e, phi) == 1:
            return RSAKey(p, q, n, e, pow(e, -1, phi))


def rsa_encrypt_int(message: int, key: RSAKey) -> int:
    if not isinstance(message, int) or not 0 <= message < key.n:
        raise ValueError("M має бути цілим числом у межах 0 <= M < n")
    return pow(message, key.e, key.n)


def rsa_decrypt_int(ciphertext: int, key: RSAKey) -> int:
    if not isinstance(ciphertext, int) or not 0 <= ciphertext < key.n:
        raise ValueError("C має бути цілим числом у межах 0 <= C < n")
    return pow(ciphertext, key.d, key.n)


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_encrypt_text(text: str, public_key: rsa.RSAPublicKey) -> str:
    """UTF-8 -> блоки RSA OAEP SHA256 -> Base64. Для 2048 біт блок до 190 байт."""
    data = text.encode("utf-8")
    limit = (public_key.key_size + 7) // 8 - 2 * hashes.SHA256().digest_size - 2
    blocks = (public_key.encrypt(data[i:i + limit], _oaep()) for i in range(0, len(data), limit))
    return base64.b64encode(b"".join(blocks)).decode("ascii")


def rsa_decrypt_text(ciphertext_b64: str, private_key: rsa.RSAPrivateKey) -> str:
    try:
        data = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Некоректний Base64") from exc
    block_size = (private_key.key_size + 7) // 8
    if len(data) % block_size:
        raise ValueError("Неповний блок RSA")
    # Спочатку об'єднання байтів, потім UTF-8: літера може перетинати межу блоків.
    decoded = b"".join(private_key.decrypt(data[i:i + block_size], _oaep())
                       for i in range(0, len(data), block_size))
    return decoded.decode("utf-8")
