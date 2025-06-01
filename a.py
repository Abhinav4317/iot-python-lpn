# import random

# def generate_random_binary_vector(size=128):
#     """Generates a random binary vector of the specified size."""
#     return [random.randint(0, 1) for _ in range(size)]

# # Generate a vector of 384 random bits
# random_vector = generate_random_binary_vector()
# print(random_vector)

import os

# Generate a 16-byte nonce
nonce = os.urandom(16)

# Convert to hexadecimal
nonce_hex = nonce.hex()

print("Nonce (hex):", nonce_hex)