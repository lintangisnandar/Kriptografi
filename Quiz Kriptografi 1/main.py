import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Vigenere Cipher
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

# Playfair Cipher
def generate_playfair_square(key):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'  # 'j' is omitted in Playfair cipher
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))  # Remove duplicates
    key = key.replace('j', 'i')  # Treat 'j' as 'i'
    square = []

    for char in key:
        if char not in square:
            square.append(char)
    for char in alphabet:
        if char not in square:
            square.append(char)

    return [square[i:i+5] for i in range(0, len(square), 5)]  # 5x5 matrix

def find_position(char, square):
    for i, row in enumerate(square):
        if char in row:
            return i, row.index(char)
    return None

# Playfair Cipher Encryption
def playfair_encrypt(plaintext, key):
    square = generate_playfair_square(key.lower())
    plaintext = plaintext.replace('j', 'i').replace(' ', '').lower()

    # Prepare digraphs (pairs of letters)
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
            # Same row
            ciphertext += square[row_a][(col_a + 1) % 5]
            ciphertext += square[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            # Same column
            ciphertext += square[(row_a + 1) % 5][col_a]
            ciphertext += square[(row_b + 1) % 5][col_b]
        else:
            # Rectangle rule
            ciphertext += square[row_a][col_b]
            ciphertext += square[row_b][col_a]

    return ciphertext

# Playfair Cipher Decryption
def playfair_decrypt(ciphertext, key):
    square = generate_playfair_square(key.lower())

    digraphs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]

    plaintext = ''
    for a, b in digraphs:
        row_a, col_a = find_position(a, square)
        row_b, col_b = find_position(b, square)

        if row_a == row_b:
            # Same row
            plaintext += square[row_a][(col_a - 1) % 5]
            plaintext += square[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            # Same column
            plaintext += square[(row_a - 1) % 5][col_a]
            plaintext += square[(row_b - 1) % 5][col_b]
        else:
            # Rectangle rule
            plaintext += square[row_a][col_b]
            plaintext += square[row_b][col_a]

    # Remove potential dummy 'x' or 'z' characters
    # Decrypt usually adds extra characters like 'x' (or 'z') between double letters or at the end.
    plaintext_fixed = ''
    i = 0
    while i < len(plaintext):
        plaintext_fixed += plaintext[i]
        # Skip the 'x' if it's a dummy letter between double letters
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i + 1]:
            i += 1
        i += 1

    return plaintext_fixed

import numpy as np

# Hill Cipher
def mod_inverse(a, m):
    # Menghitung invers modulo a mod m menggunakan Extended Euclidean Algorithm
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.lower().replace(" ", "")
    n = len(key_matrix)  # Ukuran matriks (misalnya 3x3)
    
    # Padding jika plaintext tidak sesuai ukuran matriks
    while len(plaintext) % n != 0:
        plaintext += 'x'
    
    # Convert plaintext menjadi vektor angka
    plaintext_vector = [ord(char) - ord('a') for char in plaintext]
    
    # Pisahkan plaintext menjadi blok sesuai ukuran matriks
    ciphertext = ''
    for i in range(0, len(plaintext_vector), n):
        block = np.array(plaintext_vector[i:i + n])
        # Perkalian matriks (key_matrix * block) mod 26
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext += ''.join(chr(num + ord('a')) for num in encrypted_block)
    
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    n = len(key_matrix)  # Ukuran matriks (misalnya 3x3)
    
    # Cari invers dari matriks kunci
    det = int(np.round(np.linalg.det(key_matrix)))  # Determinan
    det_inv = mod_inverse(det, 26)  # Invers determinan modulo 26
    
    if det_inv is None:
        raise ValueError("Matriks kunci tidak bisa di-invert.")
    
    # Cari invers matriks kunci (mod 26)
    key_matrix_inv = np.linalg.inv(key_matrix) * det
    key_matrix_inv = np.round(key_matrix_inv).astype(int) % 26
    key_matrix_inv = (det_inv * key_matrix_inv) % 26
    
    # Convert ciphertext menjadi vektor angka
    ciphertext_vector = [ord(char) - ord('a') for char in ciphertext]
    
    # Pisahkan ciphertext menjadi blok sesuai ukuran matriks
    plaintext = ''
    for i in range(0, len(ciphertext_vector), n):
        block = np.array(ciphertext_vector[i:i + n])
        # Perkalian matriks (key_matrix_inv * block) mod 26
        decrypted_block = np.dot(key_matrix_inv, block) % 26
        plaintext += ''.join(chr(int(num) + ord('a')) for num in decrypted_block)
    
    return plaintext

# Buka file dialog
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            data = file.read()
        text_input.delete("1.0", tk.END)
        text_input.insert(tk.END, data)

# Save file dialog
def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(result_output.get("1.0", tk.END))

# Encryption button
def encrypt():
    plaintext = text_input.get("1.0", tk.END).strip()
    key = key_input.get()
    cipher_choice = cipher_var.get()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci minimal 12 karakter")
        return
    
    if cipher_choice == "Vigenere":
        encrypted_text = vigenere_encrypt(plaintext, key)
    elif cipher_choice == "Playfair":
        encrypted_text = playfair_encrypt(plaintext, key)
    elif cipher_choice == "Hill":
        # Hill cipher example using default 3x3 matrix
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # Default key matrix 3x3
        encrypted_text = hill_encrypt(plaintext, key_matrix)
    else:
        messagebox.showerror("Error", "Pilih cipher")
        return
    
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, encrypted_text)

# Decryption button
def decrypt():
    ciphertext = text_input.get("1.0", tk.END).strip()
    key = key_input.get()
    cipher_choice = cipher_var.get()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci minimal 12 karakter")
        return
    
    if cipher_choice == "Vigenere":
        decrypted_text = vigenere_decrypt(ciphertext, key)
    elif cipher_choice == "Playfair":
        decrypted_text = playfair_decrypt(ciphertext, key)
    elif cipher_choice == "Hill":
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # Default key matrix 3x3
        decrypted_text = hill_decrypt(ciphertext, key_matrix)
    else:
        messagebox.showerror("Error", "Pilih cipher")
        return
    
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, decrypted_text)

# GUI
root = tk.Tk()
root.title("Kriptografi")

cipher_var = tk.StringVar(value="Vigenere")
tk.Radiobutton(root, text="Vigenere Cipher", variable=cipher_var, value="Vigenere").grid(row=0, column=0, sticky='w')
tk.Radiobutton(root, text="Playfair Cipher", variable=cipher_var, value="Playfair").grid(row=1, column=0, sticky='w')
tk.Radiobutton(root, text="Hill Cipher", variable=cipher_var, value="Hill").grid(row=2, column=0, sticky='w')

tk.Label(root, text="Input:").grid(row=3, column=0, sticky='w')
text_input = tk.Text(root, height=10, width=50)
text_input.grid(row=4, column=0, columnspan=2)

tk.Label(root, text="Key:").grid(row=5, column=0, sticky='w')
key_input = tk.Entry(root, width=50)
key_input.grid(row=6, column=0, columnspan=2)

tk.Button(root, text="Open File", command=load_file).grid(row=7, column=0)
tk.Button(root, text="Encrypt", command=encrypt).grid(row=8, column=0)
tk.Button(root, text="Decrypt", command=decrypt).grid(row=9, column=0)
tk.Button(root, text="Save File", command=save_file).grid(row=10, column=0)

tk.Label(root, text="Output:").grid(row=11, column=0, sticky='w')
result_output = tk.Text(root, height=10, width=50)
result_output.grid(row=12, column=0, columnspan=2)

root.mainloop()