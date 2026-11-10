"""Run all four tasks and save actual results. No persistent private key files."""
import json
from pathlib import Path
import sys
from crypto_lab import (caesar, caesar_bruteforce, normalize_ukrainian, vigenere,
                        generate_rsa_key, rsa_encrypt_int, rsa_decrypt_int,
                        rsa_encrypt_text, rsa_decrypt_text, UKRAINIAN)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def main():
    out = Path(__file__).parent / "results"
    out.mkdir(exist_ok=True)
    ciphertext = "vppanlwxlyopyncjae"
    candidates = caesar_bruteforce(ciphertext)
    t1 = "TASK 1  CAESAR\nCiphertext: " + ciphertext + "\n" + "\n".join(
        f"key={key:2d}  {text}" for key, text in candidates)
    t1 += "\nSelected key: 11\nPlaintext: keepcalmandencrypt\nRe-encryption matches: " + str(caesar(candidates[11][1], 11) == ciphertext)
    original = "криптографічнiметодизахистуінформації"
    normalized, key = normalize_ukrainian(original), "кобзей"
    encrypted = vigenere(original, key)
    restored = vigenere(encrypted, key, decrypt=True)
    t2 = f"TASK 2  VIGENERE\nAlphabet ({len(UKRAINIAN)}): {UKRAINIAN}\nSource: {original}\nNormalized: {normalized}\nKey: {key}\nEncrypted: {encrypted}\nDecrypted: {restored}\nRound trip: {restored == normalized}"
    print("Generating random 2048-bit RSA key...", flush=True)
    rsa_key = generate_rsa_key()
    c = rsa_encrypt_int(100, rsa_key)
    m = rsa_decrypt_int(c, rsa_key)
    results = {"caesar": {"ciphertext": ciphertext, "candidates": candidates, "key": 11,
                         "plaintext": candidates[11][1]},
               "vigenere": {"original": original, "normalized": normalized, "key": key,
                            "ciphertext": encrypted, "decrypted": restored},
               "rsa_number": {"bits": rsa_key.n.bit_length(), "p": str(rsa_key.p), "q": str(rsa_key.q),
                              "n": str(rsa_key.n), "phi": str(rsa_key.phi), "e": rsa_key.e,
                              "d": str(rsa_key.d), "M": 100, "C": str(c), "decrypted": m}}
    # Full generated values are retained locally as explicitly educational one-run results.
    t3 = "TASK 3  RSA NUMBER\nProgrammatically generated p and q (Miller-Rabin, 40 rounds)\n" + "\n".join(
        f"{name} = {getattr(rsa_key, name)}" for name in ("p", "q", "n", "phi", "e", "d"))
    t3 += f"\nM = 100\nC = {c}\nDecrypted = {m}\nRound trip: {m == 100}"
    private = rsa_key.private_key()
    public = private.public_key()
    sample = "Cryptography is fun and educational! Learning RSA encryption and decryption with Python helps understand public key cryptosystems."
    cases = {"given": sample, "ukrainian": "Криптографія — це цікаво! Привіт, Україно 🇺🇦 🔐", "long": "Довільний UTF-8 текст 🔐 " * 300, "empty": ""}
    text_results, lines = {}, ["TASK 4  RSA OAEP SHA256 / UTF-8 / Base64", "Key: 2048 bits; plaintext block <= 190 bytes; ciphertext block = 256 bytes"]
    for name, text in cases.items():
        encoded = rsa_encrypt_text(text, public)
        back = rsa_decrypt_text(encoded, private)
        text_results[name] = {"text": text, "utf8_bytes": len(text.encode()), "base64": encoded,
                              "blocks": len(__import__('base64').b64decode(encoded)) // 256, "match": back == text}
        lines += [f"{name}: {len(text.encode())} bytes; {text_results[name]['blocks']} blocks; match={back == text}"]
        if name == "given":
            lines += [f"Original: {text}", f"Base64: {encoded}", f"Decrypted: {back}"]
    t4 = "\n".join(lines)
    results["rsa_text"] = text_results
    assert restored == normalized and m == 100 and all(item["match"] for item in text_results.values())
    for name, value in (("01-caesar.txt", t1), ("02-vigenere.txt", t2), ("03-rsa-number.txt", t3), ("04-rsa-text.txt", t4)):
        (out / name).write_text(value + "\n", encoding="utf-8")
        print(value + "\n")
    (out / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print("ALL FOUR TASKS PASSED")

if __name__ == "__main__":
    main()
