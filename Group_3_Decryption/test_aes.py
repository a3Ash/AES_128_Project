from aes_decrypt import inv_sub_bytes, inv_shift_rows

SBOX = [(i + 1) % 256 for i in range(256)]

INV_SBOX = [0] * 256

for index, value in enumerate(SBOX):
    INV_SBOX[value] = index
    
original_state = [
    [0x00, 0x01, 0x02, 0x03],
    [0x04, 0x05, 0x06, 0x07],
    [0x08, 0x09, 0x0A, 0x0B],
    [0x0C, 0x0D, 0x0E, 0x0F]
]

state = [row[:] for row in original_state]

for row in range(4):
    for col in range(4):
        state[row][col] = SBOX[state[row][col]]


print("After Dummy SubBytes:")

for row in state:
    print(" ".join(f"{x:02X}" for x in row))
    
inv_sub_bytes(state, INV_SBOX)


print("\nAfter InvSubBytes:")

for row in state:
    print(" ".join(f"{x:02X}" for x in row))

assert state == original_state

print("\nSUCCESS: Original State Recovered!")

for i in range(256):
    assert INV_SBOX[SBOX[i]] == i

print("SUCCESS: All 256 Mappings Verified!")



# =====================================
# Test InvShiftRows
# =====================================

original_state = [
    [0x00, 0x01, 0x02, 0x03],
    [0x10, 0x11, 0x12, 0x13],
    [0x20, 0x21, 0x22, 0x23],
    [0x30, 0x31, 0x32, 0x33]
]

# Expected output
expected_state = [
    [0x00, 0x01, 0x02, 0x03],
    [0x13, 0x10, 0x11, 0x12],
    [0x22, 0x23, 0x20, 0x21],
    [0x31, 0x32, 0x33, 0x30]
]

# Copy original state
state = [row[:] for row in original_state]

# Apply InvShiftRows
inv_shift_rows(state)

print("After InvShiftRows:")

for row in state:
    print(" ".join(f"{x:02X}" for x in row))

# Verify
assert state == expected_state

print("\nSUCCESS: InvShiftRows Test Passed!")
