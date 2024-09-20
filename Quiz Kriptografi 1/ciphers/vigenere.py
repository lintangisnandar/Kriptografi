def vigenere_encrypt(plaintext, key):
    key = key.lower()
    ciphertext = ''
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if plaintext[i].isupper():
                ciphertext += chr((ord(plaintext[i]) - ord('A') + shift) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(plaintext[i]) - ord('a') + shift) % 26 + ord('a'))
        else:
            ciphertext += plaintext[i]
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    plaintext = ''
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if ciphertext[i].isupper():
                plaintext += chr((ord(ciphertext[i]) - ord('A') - shift + 26) % 26 + ord('A'))
            else:
                plaintext += chr((ord(ciphertext[i]) - ord('a') - shift + 26) % 26 + ord('a'))
        else:
            plaintext += ciphertext[i]
    return plaintext
