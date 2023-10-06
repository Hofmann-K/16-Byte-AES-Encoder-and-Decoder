# Import the AES S-box from the sbox module
from sbox import get_s_box
# Import the AES inverted S-Box from the invsbox module
from invsbox import get_inv_s_box

# Define the AES S-box
s_box = get_s_box()
inv_s_box = get_inv_s_box()

# Define the round constant values for key expansion (Rcon)
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# AES SubBytes transformation
def sub_bytes(state):
    for i in range(16):
        state[i] = s_box[state[i]]
    return state

# AES ShiftRows transformation
def shift_rows(state):
    new_state = [0] * 16
    for i in range(4):
        for j in range(4):
            new_state[i + j * 4] = state[(i + j * 4 + (i * 4)) % 16]
    return new_state

# Function to perform Xtime (linear feedback shift register)
def Xtime(a, b):
    # Perform the Xtime operation (xtime) as specified in AES
    result = 0
    for _ in range(8):
        if b & 0x01:
            result ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x1B  # XOR with 0x1B if high bit was set
        b >>= 1
    return result & 0xFF

# AES MixColumns transformation
def mix_columns(state):
    new_state = [0] * 16
    mix_columns_matrix = [
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    ]

    for col in range(4):
        for row in range(4):
            result = 0
            for i in range(4):
                result ^= Xtime(mix_columns_matrix[row * 4 + i], state[col + i * 4])
            new_state[col + row * 4] = result
    return new_state

# AES Inverse MixColumns transformation
def inv_mix_columns(state):
    new_state = [0] * 16
    inv_mix_columns_matrix = [
        0x0E, 0x0B, 0x0D, 0x09,
        0x09, 0x0E, 0x0B, 0x0D,
        0x0D, 0x09, 0x0E, 0x0B,
        0x0B, 0x0D, 0x09, 0x0E
    ]

    for col in range(4):
        for row in range(4):
            result = 0
            for i in range(4):
                result ^= Xtime(inv_mix_columns_matrix[row * 4 + i], state[col + i * 4])
            new_state[col + row * 4] = result
    return new_state

# AES AddRoundKey transformation
def add_round_key(state, key):
    for i in range(16):
        state[i] ^= key[i]
    return state

# AES encryption for a 16-byte input with a 16-byte key
def aes_encrypt(input_data, key):
    state = list(input_data)
    
    # Initial round key addition
    state = add_round_key(state, key)

    # Main rounds (9 rounds)
    for round_num in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)  # Add MixColumns here
        state = add_round_key(state, key)

    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key)

    return bytes(state)

# AES decryption for a 16-byte input with a 16-byte key
def aes_decrypt(encrypted_data, key):
    state = list(encrypted_data)
    
    # Initial round key addition
    state = add_round_key(state, key)

    # Inverse Main rounds (9 rounds)
    for round_num in range(9):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, key)
        state = inv_mix_columns(state)  # Add inverse MixColumns here

    # Inverse Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key)

    return bytes(state)

# AES Inverse SubBytes transformation
def inv_sub_bytes(state):
    for i in range(16):
        state[i] = inv_s_box[state[i]]
    return state

# AES Inverse ShiftRows transformation
def inv_shift_rows(state):
    new_state = [0] * 16
    for i in range(4):
        for j in range(4):
            new_state[i + j * 4] = state[(i + j * 4 - (i * 4)) % 16]
    return new_state

# Function to input data (plaintext or key) and convert to binary
def input_data(prompt):
    while True:
        data = input(prompt).strip()
        if len(data) == 16:
            return data.encode('utf-8')  # Convert input to binary (not hexadecimal)
        else:
            print("Input must be exactly 16 bytes long. Please try again.")

# Function to ask whether to encode or decode
def ask_operation():
    while True:
        operation = input("Choose an operation (encode/decode): ").strip().lower()
        if operation in ['encode', 'decode']:
            return operation
        else:
            print("Invalid operation. Please choose 'encode' or 'decode'.")

if __name__ == "__main__":
    print("AES Encryption and Decryption")

    while True:
        operation = ask_operation()

        if operation == 'encode':
            # Get user input for plaintext and key
            plaintext = input_data("Enter the input data (16 bytes): ")
            key = input_data("Enter the encryption key (16 bytes): ")

            # Encrypt the data
            encrypted_data = aes_encrypt(plaintext, key)
            print("Encrypted Data (in hexadecimal):", encrypted_data.hex())
        else:
            # Get user input for encrypted data and key
            encrypted_data_hex = input("Enter the encrypted data (in hexadecimal): ")
            decryption_key = input_data("Enter the decryption key (16 bytes): ")

            # Convert the hex string to bytes
            encrypted_data = bytes.fromhex(encrypted_data_hex)

            # Decrypt the data
            decrypted_data = aes_decrypt(encrypted_data, decryption_key)
            print("Decrypted Data:", decrypted_data.decode('utf-8', errors='ignore'))

        another_operation = input("Do you want to perform another operation? (yes/no): ").strip().lower()
        if another_operation != 'yes':
            break
