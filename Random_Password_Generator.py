import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        self.length_var = tk.IntVar()
        self.use_letters_var = tk.BooleanVar()
        self.use_numbers_var = tk.BooleanVar()
        self.use_symbols_var = tk.BooleanVar()

        self.init_ui()

    def generate_password(self):
        length = self.length_var.get()
        use_letters = self.use_letters_var.get()
        use_numbers = self.use_numbers_var.get()
        use_symbols = self.use_symbols_var.get()

        characters = ""
        if use_letters:
            characters += string.ascii_letters
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Please select at least one character set.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.display_password(password)

    def display_password(self, password):
        self.result_var.set(password)
        pyperclip.copy(password)  # Copy password to clipboard
        messagebox.showinfo("Password Generated", "Password copied to clipboard!")

    def init_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(main_frame, text="Password Length:").grid(column=0, row=0, sticky=tk.W)
        length_entry = ttk.Entry(main_frame, textvariable=self.length_var)
        length_entry.grid(column=1, row=0, sticky=tk.W)

        ttk.Checkbutton(main_frame, text="Include Letters", variable=self.use_letters_var).grid(column=0, row=1, sticky=tk.W)
        ttk.Checkbutton(main_frame, text="Include Numbers", variable=self.use_numbers_var).grid(column=1, row=1, sticky=tk.W)
        ttk.Checkbutton(main_frame, text="Include Symbols", variable=self.use_symbols_var).grid(column=2, row=1, sticky=tk.W)

        generate_button = ttk.Button(main_frame, text="Generate Password", command=self.generate_password)
        generate_button.grid(column=0, row=2, columnspan=3, pady=10)

        ttk.Label(main_frame, text="Generated Password:").grid(column=0, row=3, columnspan=3, sticky=tk.W)
        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(main_frame, textvariable=self.result_var, state="readonly")
        result_entry.grid(column=0, row=4, columnspan=3, sticky=(tk.W, tk.E))
        result_entry.bind("<Button-1>", lambda e: self.display_password(pyperclip.paste()))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
