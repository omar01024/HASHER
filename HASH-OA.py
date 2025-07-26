# © 2025 Omar Ayman. All rights reserved.
# This software is licensed for personal and educational use only.

import tkinter as tk
import hashlib
import pyperclip

def encrypt():
    text = entry.get()
    algorithm = hash_type.get()
    if algorithm == "SHA-256":
        hashed = hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "SHA-1":
        hashed = hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == "MD5":
        hashed = hashlib.md5(text.encode()).hexdigest()
    else:
        hashed = "Unsupported algorithm."

    result_label.config(text=hashed)
    global last_hash
    last_hash = hashed

def copy_hash():
    if result_label.cget("text"):
        pyperclip.copy(result_label.cget("text"))

def compare_hashes():
    hash1 = result_label.cget("text")
    hash2 = compare_entry.get()
    if not hash1 or not hash2:
        compare_result.config(text="Please generate and enter both hashes.", fg="red")
    elif hash1.strip() == hash2.strip():
        compare_result.config(text="✅ Hashes match!", fg="green")
    else:
        compare_result.config(text="❌ Hashes do NOT match.", fg="red")

# GUI
root = tk.Tk()
root.title("Multi-Hash Hasher")
root.geometry("600x470")

# Entry and Encrypt
tk.Label(root, text="Enter text:", font=("Arial", 14)).pack(pady=10)
entry = tk.Entry(root, width=60)
entry.pack()

# Hash Type Selection
tk.Label(root, text="Choose hash algorithm:", font=("Arial", 12)).pack(pady=5)
hash_type = tk.StringVar(value="SHA-256")
tk.OptionMenu(root, hash_type, "SHA-256", "SHA-1", "MD5").pack()

# Encrypt Button
tk.Button(root, text="Encrypt", command=encrypt).pack(pady=10)

# Result Label
result_label = tk.Label(root, text="", wraplength=560, font=("Courier", 10))
result_label.pack(pady=5)

# Copy Button
tk.Button(root, text="Copy Hash", command=copy_hash).pack(pady=5)

# Compare Section
tk.Label(root, text="Enter another hash to compare:", font=("Arial", 12)).pack(pady=10)
compare_entry = tk.Entry(root, width=60)
compare_entry.pack()

# Compare Button
tk.Button(root, text="Compare Hashes", command=compare_hashes).pack(pady=5)
compare_result = tk.Label(root, text="", font=("Arial", 12))
compare_result.pack(pady=5)

# Copyright Label
copyright_label = tk.Label(
    root,
    text="© 2025 Omar Ayman | All rights reserved.",
    font=("Arial", 8),
    fg="gray"
)
copyright_label.pack(pady=5)

root.mainloop()
