def generate_playfair_square(key):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))
    key = key.replace('j', 'i')
    square = []

    for char in key:
        if char not in square:
            square.append(char)
    for char in alphabet:
        if char not in square:
            square.append(char)

    return [square[i:i+5] for i in range(0, len(square), 5)]

def find_position(char, square):
    for i, row in enumerate(square):
        if char in row:
            return i, row.index(char)
    return None

def playfair_encrypt(plaintext, key):
    square = generate_playfair_square(key.lower())
    plaintext = plaintext.replace('j', 'i').replace(' ', '').lower()

    digraphs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 < len(plaintext) and plaintext[i + 1] != a:
            b = plaintext[i + 1]
            i += 2
        else:
            b = 'x' if a != 'x' else 'z'
            i += 1
        digraphs.append((a, b))

    ciphertext = ''
    for a, b in digraphs:
        row_a, col_a = find_position(a, square)
        row_b, col_b = find_position(b, square)

        if row_a == row_b:
            ciphertext += square[row_a][(col_a + 1) % 5]
            ciphertext += square[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            ciphertext += square[(row_a + 1) % 5][col_a]
            ciphertext += square[(row_b + 1) % 5][col_b]
        else:
            ciphertext += square[row_a][col_b]
            ciphertext += square[row_b][col_a]

    return ciphertext

def playfair_decrypt(ciphertext, key):
    square = generate_playfair_square(key.lower())

    digraphs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]

    plaintext = ''
    for a, b in digraphs:
        row_a, col_a = find_position(a, square)
        row_b, col_b = find_position(b, square)

        if row_a == row_b:
            plaintext += square[row_a][(col_a - 1) % 5]
            plaintext += square[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            plaintext += square[(row_a - 1) % 5][col_a]
            plaintext += square[(row_b - 1) % 5][col_b]
        else:
            plaintext += square[row_a][col_b]
            plaintext += square[row_b][col_a]

    plaintext_fixed = ''
    i = 0
    while i < len(plaintext):
        plaintext_fixed += plaintext[i]
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            i += 1
        i += 1

    return plaintext_fixed