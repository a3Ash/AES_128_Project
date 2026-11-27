# Group 3 — AES-128 Decryption

Group 3 implements AES-128 block decryption. [Group 1](../Group_1_Key_Expansion) handles key expansion, and [Group 2](../Group_2_Encryption) handles encryption.

## Files

| File | Purpose |
| --- | --- |
| [`aes_decrypt.py`](aes_decrypt.py) | Implements the AES-128 inverse cipher and exposes `decrypt_block(ciphertext, key)`. |
| [`test_aes.py`](test_aes.py) | Tests the inverse transformations, round keys, input validation, and decryption using NIST test vectors. |

## Decrypt a block

Run this example from the project root in Python 3. The function takes one 16-byte ciphertext block and the original 16-byte key used for encryption. It returns one 16-byte plaintext block as `bytes`.

```python
from Group_3_Decryption.aes_decrypt import decrypt_block

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

plaintext = decrypt_block(ciphertext, key)
print(plaintext.hex())  # 00112233445566778899aabbccddeeff
```

The module includes key expansion so Group 3 can run its tests independently. To test Group 2's output, pass its raw ciphertext block and the same original key to `decrypt_block`. If the ciphertext is given as hexadecimal text, convert it with `bytes.fromhex()` first.

## Decryption steps

1. Load the ciphertext column by column into a 4×4 byte state and apply `AddRoundKey` with `K10`.
2. For keys `K9` through `K1`, apply `InvShiftRows`, `InvSubBytes`, `AddRoundKey`, and `InvMixColumns` in that order.
3. Apply `InvShiftRows`, `InvSubBytes`, and `AddRoundKey` with `K0`, then read the plaintext column by column.

## Run the tests

From the project root, run this command. Python 3 is the only requirement.

```powershell
python -m unittest Group_3_Decryption.test_aes -v
```

If your terminal is already open in `Group_3_Decryption`, run `python test_aes.py -v`. The expected result is `Ran 11 tests` followed by `OK`.

## References

- [NIST FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST AES-128 example vectors](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf)
