import numpy as np

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.lower().replace(" ", "")
    n = len(key_matrix)
    while len(plaintext) % n != 0:
        plaintext += 'x'
    plaintext_vector = [ord(char) - ord('a') for char in plaintext]
    ciphertext = ''
    for i in range(0, len(plaintext_vector), n):
        block = np.array(plaintext_vector[i:i + n])
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext += ''.join(chr(num + ord('a')) for num in encrypted_block)
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    n = len(key_matrix)
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        raise ValueError("Matriks kunci tidak bisa di-invert.")
    key_matrix_inv = np.linalg.inv(key_matrix) * det
    key_matrix_inv = np.round(key_matrix_inv).astype(int) % 26
    key_matrix_inv = (det_inv * key_matrix_inv) % 26
    ciphertext_vector = [ord(char) - ord('a') for char in ciphertext]
    plaintext = ''
    for i in range(0, len(ciphertext_vector), n):
        block = np.array(ciphertext_vector[i:i + n])
        decrypted_block = np.dot(key_matrix_inv, block) % 26
        plaintext += ''.join(chr(int(num) + ord('a')) for num in decrypted_block)
    return plaintext