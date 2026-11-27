"""AES-128 inverse cipher for decrypting a single block."""

_BLOCK_SIZE = 16
_ROUNDS = 10

# Forward S-box from FIPS 197, used for key expansion.
SBOX = bytes.fromhex(
    "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 "
    "ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 "
    "b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 "
    "04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 "
    "09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 "
    "53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf "
    "d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 "
    "51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 "
    "cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 "
    "60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db "
    "e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 "
    "e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 "
    "ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a "
    "70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e "
    "e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df "
    "8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16"
)

_inverse_sbox = bytearray(256)
for _index, _value in enumerate(SBOX):
    _inverse_sbox[_value] = _index
INV_SBOX = bytes(_inverse_sbox)

_INV_MIX_MATRIX = (
    (0x0E, 0x0B, 0x0D, 0x09),
    (0x09, 0x0E, 0x0B, 0x0D),
    (0x0D, 0x09, 0x0E, 0x0B),
    (0x0B, 0x0D, 0x09, 0x0E),
)


def inv_sub_bytes(state, inv_sbox=INV_SBOX):
    """Replace each byte using the inverse S-box and return the modified state."""
    for row in range(4):
        for column in range(4):
            state[row][column] = inv_sbox[state[row][column]]
    return state


def inv_shift_rows(state):
    """Rotate each row right by its row index and return the modified state."""
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]
    return state


def _xtime(value):
    """Multiply by x and reduce modulo the AES polynomial."""
    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value


def _gf_multiply(value, coefficient):
    """Multiply two bytes in the AES finite field."""
    product = 0
    while coefficient:
        if coefficient & 1:
            product ^= value
        value = _xtime(value)
        coefficient >>= 1
    return product


def inv_mix_columns(state):
    """Apply the inverse MixColumns matrix to each column in place."""
    for column in range(4):
        original = [state[row][column] for row in range(4)]
        for row, coefficients in enumerate(_INV_MIX_MATRIX):
            mixed = 0
            for value, coefficient in zip(original, coefficients):
                mixed ^= _gf_multiply(value, coefficient)
            state[row][column] = mixed
    return state


def add_round_key(state, round_key):
    """XOR a 16-byte round key into the state in column order."""
    for row in range(4):
        for column in range(4):
            state[row][column] ^= round_key[4 * column + row]
    return state


def _as_block(value, name):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be a bytes-like object")
    block = bytes(value)
    if len(block) != _BLOCK_SIZE:
        raise ValueError(f"{name} must be exactly {_BLOCK_SIZE} bytes")
    return block


def expand_key(key):
    """Return the eleven AES-128 round keys in encryption order."""
    key = _as_block(key, "key")
    words = [key[offset:offset + 4] for offset in range(0, _BLOCK_SIZE, 4)]
    round_constant = 0x01

    for index in range(4, 4 * (_ROUNDS + 1)):
        word = words[-1]
        if index % 4 == 0:
            rotated = word[1:] + word[:1]
            substituted = [SBOX[value] for value in rotated]
            substituted[0] ^= round_constant
            word = substituted
            round_constant = _xtime(round_constant)
        previous_round_word = words[index - 4]
        words.append(bytes(left ^ right for left, right in zip(previous_round_word, word)))

    return [b"".join(words[offset:offset + 4]) for offset in range(0, len(words), 4)]


def decrypt_block(ciphertext, key):
    """Decrypt one 16-byte AES-128 ciphertext block with a 16-byte key.

    Both inputs accept bytes, bytearray, or memoryview. The result is bytes.
    """
    ciphertext = _as_block(ciphertext, "ciphertext")
    round_keys = expand_key(key)

    # AES maps consecutive groups of four bytes to columns of the state.
    state = [list(ciphertext[row::4]) for row in range(4)]
    add_round_key(state, round_keys[-1])

    for round_key in reversed(round_keys[1:-1]):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_key)
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return bytes(value for column in zip(*state) for value in column)


    return state

