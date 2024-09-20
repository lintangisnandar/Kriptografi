import tkinter as tk
from tkinter import filedialog, messagebox
from ciphers.vigenere import vigenere_encrypt, vigenere_decrypt
from ciphers.playfair import playfair_encrypt, playfair_decrypt
from ciphers.hill import hill_encrypt, hill_decrypt

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