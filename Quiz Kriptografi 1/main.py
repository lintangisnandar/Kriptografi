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

#Playfair Cipher
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
    pass

def playfair_decrypt(ciphertext, key):
    pass

#Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    pass

def hill_decrypt(ciphertext, key_matrix):
    pass

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
    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long")
        return
    encrypted_text = vigenere_encrypt(plaintext, key)  # Example using Vigenere Cipher
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, encrypted_text)

# Decryption button
def decrypt():
    ciphertext = text_input.get("1.0", tk.END).strip()
    key = key_input.get()
    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long")
        return
    decrypted_text = vigenere_decrypt(ciphertext, key)  # Example using Vigenere Cipher
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, decrypted_text)

# GUI
root = tk.Tk()
root.title("Kriptografi")

tk.Label(root, text="Input:").grid(row=0, column=0)
text_input = tk.Text(root, height=10, width=50)
text_input.grid(row=1, column=0, columnspan=2)

tk.Label(root, text="Key:").grid(row=2, column=0)
key_input = tk.Entry(root, width=50)
key_input.grid(row=2, column=1)

tk.Button(root, text="Open File", command=load_file).grid(row=3, column=0)
tk.Button(root, text="Encrypt", command=encrypt).grid(row=3, column=1)
tk.Button(root, text="Decrypt", command=decrypt).grid(row=4, column=1)
tk.Button(root, text="Save File", command=save_file).grid(row=4, column=0)

tk.Label(root, text="Output:").grid(row=5, column=0)
result_output = tk.Text(root, height=10, width=50)
result_output.grid(row=6, column=0, columnspan=2)

root.mainloop()