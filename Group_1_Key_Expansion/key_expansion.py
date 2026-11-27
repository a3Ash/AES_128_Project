try:
    from Group_1_Key_Expansion.aes_utils import (
        RCON,
        S_BOX,
        add_round_key,
        bytes_to_state,
        state_to_hex,
    )
except ImportError:
    from aes_utils import RCON, S_BOX, add_round_key, bytes_to_state, state_to_hex


def rot_word(word):
    """Rotate a 4-byte word left by 1 byte."""
    return word[1:] + word[:1]


def sub_word(word):
    """Substitute each byte in a 4-byte word using the S-Box."""
    result = []
    for byte in word:
        result.append(S_BOX[byte])
    return result


def xor_words(w1, w2):
    """XOR two 4-byte words."""
    result = []
    for i in range(4):
        result.append(w1[i] ^ w2[i])
    return result


def key_expansion(key_hex):
    """Generate 11 round keys (K0-K10) as 32-char hex strings from a 128-bit hex key."""
    key_bytes = bytes.fromhex(key_hex)

    # First 4 words come directly from the secret key
    words = []
    for i in range(0, 16, 4):
        words.append(list(key_bytes[i : i + 4]))

    # Expand into 44 words total (4 words per round key)
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[(i // 4) - 1]
        words.append(xor_words(words[i - 4], temp))

    # Group every 4 words into a 4x4 column-major round key, then convert to hex
    round_keys = []
    for i in range(0, 44, 4):
        rk = []
        for row in range(4):
            current_row = []
            for col in range(4):
                current_row.append(words[i + col][row])
            rk.append(current_row)
        round_keys.append(state_to_hex(rk))

    return round_keys


def initial_processing(plaintext_hex, key_hex):
    """
    Interface for Group 2:
    Returns (initial_state_hex, round_keys_hex) after initial AddRoundKey.
    """
    plaintext_bytes = bytes.fromhex(plaintext_hex)
    state = bytes_to_state(plaintext_bytes)
    round_keys = key_expansion(key_hex)
    first_round_key = bytes_to_state(bytes.fromhex(round_keys[0]))
    initial_state = add_round_key(state, first_round_key)
    return state_to_hex(initial_state), round_keys


if __name__ == "__main__":
    plaintext = "00112233445566778899aabbccddeeff"
    secret_key = "000102030405060708090a0b0c0d0e0f"

    initial_state, round_keys = initial_processing(plaintext, secret_key)

    print("Total Round Keys:", len(round_keys))
    print("Round Key 0:", round_keys[0])
    print("Initial State:", initial_state)
