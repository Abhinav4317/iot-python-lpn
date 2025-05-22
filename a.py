import random

def generate_random_binary_vector(size=128):
    """Generates a random binary vector of the specified size."""
    return [random.randint(0, 1) for _ in range(size)]

# Generate a vector of 384 random bits
random_vector = generate_random_binary_vector()
print(random_vector)
