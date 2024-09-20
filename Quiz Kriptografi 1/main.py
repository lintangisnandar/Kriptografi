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
def generate_playfair_key_matrix(key):
    matrix = []
    key = key.lower().replace("j", "i")
    key_matrix = ""
    for c in key:
        if c not in key_matrix and c.isalpha():
            key_matrix += c
    for i in range(26):
        c = chr(i + 97)
        if c not in key_matrix and c != 'j':
            key_matrix += c
    for i in range(0, 25, 5):
        matrix.append(key_matrix[i:i+5])
    return matrix

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_key_matrix(key)
    plaintext = plaintext.lower().replace("j", "i")
    plaintext_pairs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i+1] if i+1 < len(plaintext) else 'x'
        if a == b:
            b = 'x'
            i += 1
        else:
            i += 2
        plaintext_pairs.append(a + b)
    
    ciphertext = ''
    for pair in plaintext_pairs:
        pos_a = find_position(pair[0], matrix)
        pos_b = find_position(pair[1], matrix)
        if pos_a[0] == pos_b[0]:
            ciphertext += matrix[pos_a[0]][(pos_a[1]+1) % 5]
            ciphertext += matrix[pos_b[0]][(pos_b[1]+1) % 5]
        elif pos_a[1] == pos_b[1]:
            ciphertext += matrix[(pos_a[0]+1) % 5][pos_a[1]]
            ciphertext += matrix[(pos_b[0]+1) % 5][pos_b[1]]
        else:
            ciphertext += matrix[pos_a[0]][pos_b[1]]
            ciphertext += matrix[pos_b[0]][pos_a[1]]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_key_matrix(key)
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        pos_a = find_position(a, matrix)
        pos_b = find_position(b, matrix)
        if pos_a[0] == pos_b[0]:
            plaintext += matrix[pos_a[0]][(pos_a[1]-1) % 5]
            plaintext += matrix[pos_b[0]][(pos_b[1]-1) % 5]
        elif pos_a[1] == pos_b[1]:
            plaintext += matrix[(pos_a[0]-1) % 5][pos_a[1]]
            plaintext += matrix[(pos_b[0]-1) % 5][pos_b[1]]
        else:
            plaintext += matrix[pos_a[0]][pos_b[1]]
            plaintext += matrix[pos_b[0]][pos_a[1]]
    return plaintext

def find_position(letter, matrix):
    for i, row in enumerate(matrix):
        for j, char in enumerate(row):
            if char == letter:
                return i, j
    return None

# Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    key_matrix = np.array(key_matrix)
    plaintext = [ord(c) - ord('a') for c in plaintext.lower()]
    if len(plaintext) % 3 != 0:
        plaintext += [ord('x') - ord('a')] * (3 - len(plaintext) % 3)
    ciphertext = ""
    for i in range(0, len(plaintext), 3):
        block = np.array(plaintext[i:i+3]).reshape(3, 1)
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext += ''.join([chr(int(num) + ord('a')) for num in encrypted_block.flatten()])
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    key_matrix = np.array(key_matrix)
    key_inverse = np.linalg.inv(key_matrix).astype(int) % 26
    ciphertext = [ord(c) - ord('a') for c in ciphertext.lower()]
    plaintext = ""
    for i in range(0, len(ciphertext), 3):
        block = np.array(ciphertext[i:i+3]).reshape(3, 1)
        decrypted_block = np.dot(key_inverse, block) % 26
        plaintext += ''.join([chr(int(num) + ord('a')) for num in decrypted_block.flatten()])
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