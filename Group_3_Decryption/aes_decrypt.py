# AES Decryption
# InvSubBytes Implementation

def inv_sub_bytes(state, inv_sbox):

    for row in range(4):
        for col in range(4):

            state[row][col] = inv_sbox[state[row][col]]

    return state
