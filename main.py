# Import the AES S-box from the sbox module
from sbox import get_s_box
# Import the AES inverted S-Box from the invsbox module
from invsbox import get_inv_s_box

# Define the AES S-box
s_box = get_s_box()
inv_s_box = get_inv_s_box()

# AES SubBytes transformation
def sub_bytes(state):
    for i in range(16):
        state[i] = s_box[state[i]] # Subs values from S-Box into the array
    return state

# AES ShiftRows transformation
def shift_rows(state):
    new_state = [0] * 16
    for i in range(4):
        for j in range(4):
            new_state[i + j*4] = state[(i + j*4 + (i*4)) % 16] # Stores old value and then moves it into new formation
    return new_state

# AES AddRoundKey transformation
def add_round_key(state, key):
    for i in range(16):
        state[i] ^= key[i] # Defines and sets up the encryption key
    return state

# AES encryption for a 16-byte input with a 16-byte key
def aes_encrypt(input_data, key):
    state = list(input_data)

    # Initial round key addition
    state = add_round_key(state, key)

    # Main rounds (9 rounds)
    for _ in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, key)
    # Loops through 9 times calling for the input to be subbed with S-Box vales, shifted, and changed by the key

    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key)
    # Make sure that the final round is saved (10 rounds total)

    return bytes(state)

# AES decryption for a 16-byte input with a 16-byte key
def aes_decrypt(encrypted_data, key):
    state = list(encrypted_data)

    # Initial round key addition
    state = add_round_key(state, key)

    # Inverse Main rounds (9 rounds)
    for _ in range(9):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, key)
    # Reverses the effect of the encryption

    # Inverse Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key)
    # Final round to make sure it reaches the 10 rounds

    return bytes(state)

# AES Inverse SubBytes transformation
def inv_sub_bytes(state):
    for i in range(16):
        state[i] = inv_s_box[state[i]] # Same as encryption, but using inverse S-Box as per AES
    return state

# AES Inverse ShiftRows transformation
def inv_shift_rows(state):
    new_state = [0] * 16
    for i in range(4):
        for j in range(4):
            new_state[i + j*4] = state[(i + j*4 - (i*4)) % 16] # Same as encryption, but using inverse S-Box as per AES
    return new_state

# Function to input data (plaintext or key)
def input_data(prompt):
    while True:
        data = input(prompt).strip()
        if len(data) == 16:
            return data
        else:
            print("Input must be exactly 16 bytes long. Please try again.") # Error handel in case of misinput

# Function to ask whether to encode or decode
def ask_operation():
    while True:
        operation = input("Choose an operation (encode/decode): ").strip().lower()
        if operation in ['encode', 'decode']:
            return operation
        else:
            print("Invalid operation. Please choose 'encode' or 'decode'.") # Error handel in case of misinput

# main user interations
if __name__ == "__main__":
    print("AES Encryption and Decryption")

    operation = ask_operation()

    if operation == 'encode':
        # Get user input for plaintext and key
        plaintext = input_data("Enter the input data (16 bytes): ")
        encryption_key = input_data("Enter the encryption key (16 bytes): ")

        # Encode the plaintext and key
        plaintext_bytes = plaintext.encode('utf-8')
        key_bytes = encryption_key.encode('utf-8')

        # Encrypt the data
        encrypted_data = aes_encrypt(plaintext_bytes, key_bytes)
        print("Encrypted Data (in hexadecimal):", encrypted_data.hex())
    else:
        # Get user input for encrypted data and key
        encrypted_data_hex = input("Enter the encrypted data (in hexadecimal): ")
        decryption_key = input_data("Enter the decryption key (16 bytes): ")

        # Convert the hex string to bytes
        encrypted_data = bytes.fromhex(encrypted_data_hex)
        key_bytes = decryption_key.encode('utf-8')

        # Decrypt the data
        decrypted_data = aes_decrypt(encrypted_data, key_bytes)
        print("Decrypted Data:", decrypted_data.decode('utf-8', errors='ignore'))
