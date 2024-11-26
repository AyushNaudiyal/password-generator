import random
import string
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, IntVar, StringVar
import secrets
import pyperclip

class PasswordGenerator:
    def __init__(self):
        """
        Initialize password generation parameters
        """
        self.lowercase_chars = string.ascii_lowercase
        self.uppercase_chars = string.ascii_uppercase
        self.digit_chars = string.digits
        self.special_chars = string.punctuation
    
    def generate_password(self, 
                           length=12, 
                           use_lowercase=True, 
                           use_uppercase=True, 
                           use_digits=True, 
                           use_special=True):
        """
        Generate a random password with specified criteria
        
        :param length: Length of the password
        :param use_lowercase: Include lowercase letters
        :param use_uppercase: Include uppercase letters
        :param use_digits: Include digits
        :param use_special: Include special characters
        :return: Generated password
        """
        # Validate input
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Character set selection
        char_set = []
        if use_lowercase:
            char_set.extend(list(self.lowercase_chars))
        if use_uppercase:
            char_set.extend(list(self.uppercase_chars))
        if use_digits:
            char_set.extend(list(self.digit_chars))
        if use_special:
            char_set.extend(list(self.special_chars))
        
        # Ensure at least one character from each selected category
        password = []
        if use_lowercase:
            password.append(random.choice(self.lowercase_chars))
        if use_uppercase:
            password.append(random.choice(self.uppercase_chars))
        if use_digits:
            password.append(random.choice(self.digit_chars))
        if use_special:
            password.append(random.choice(self.special_chars))
        
        # Fill the rest of the password
        while len(password) < length:
            password.append(random.choice(char_set))
        
        # Shuffle the password to randomize character positions
        random.shuffle(password)
        
        return ''.join(password)
    
    def generate_multiple_passwords(self, 
                                    count=5, 
                                    length=12, 
                                    use_lowercase=True, 
                                    use_uppercase=True, 
                                    use_digits=True, 
                                    use_special=True):
        """
        Generate multiple random passwords
        
        :param count: Number of passwords to generate
        :return: List of generated passwords
        """
        return [
            self.generate_password(
                length, 
                use_lowercase, 
                use_uppercase, 
                use_digits, 
                use_special
            ) for _ in range(count)
        ]
    
    def check_password_strength(self, password):
        """
        Evaluate password strength
        
        :param password: Password to check
        :return: Strength rating
        """
        strength = 0
        
        # Length check
        if len(password) >= 12:
            strength += 2
        elif len(password) >= 8:
            strength += 1
        
        # Character type checks
        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        # Add strength for each character type
        strength += has_lowercase
        strength += has_uppercase
        strength += has_digit
        strength += has_special
        
        # Strength classification
        if strength <= 2:
            return "Very Weak"
        elif strength <= 4:
            return "Weak"
        elif strength <= 6:
            return "Medium"
        else:
            return "Strong"

class PasswordGeneratorGUI:
    def __init__(self, master):
        """
        Initialize the GUI for Password Generator
        
        :param master: Tkinter root window
        """
        self.master = master
        master.title("Random Password Generator")
        master.geometry("600x700")
        
        # Password Generator
        self.generator = PasswordGenerator()
        
        # Password Generation Frame
        self.gen_frame = ttk.LabelFrame(master, text="Password Generation")
        self.gen_frame.pack(padx=10, pady=10, fill='x')
        
        # Length
        ttk.Label(self.gen_frame, text="Password Length:").grid(row=0, column=0, padx=5, pady=5)
        self.length_entry = ttk.Entry(self.gen_frame)
        self.length_entry.insert(0, "12")
        self.length_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Number of Passwords
        ttk.Label(self.gen_frame, text="Number of Passwords:").grid(row=0, column=2, padx=5, pady=5)
        self.count_entry = ttk.Entry(self.gen_frame)
        self.count_entry.insert(0, "5")
        self.count_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Character Type Checkboxes
        self.use_lowercase = IntVar(value=1)
        self.use_uppercase = IntVar(value=1)
        self.use_digits = IntVar(value=1)
        self.use_special = IntVar(value=1)
        
        ttk.Checkbutton(self.gen_frame, text="Lowercase", variable=self.use_lowercase).grid(row=1, column=0)
        ttk.Checkbutton(self.gen_frame, text="Uppercase", variable=self.use_uppercase).grid(row=1, column=1)
        ttk.Checkbutton(self.gen_frame, text="Digits", variable=self.use_digits).grid(row=1, column=2)
        ttk.Checkbutton(self.gen_frame, text="Special Chars", variable=self.use_special).grid(row=1, column=3)
        
        # Generate Button
        ttk.Button(self.gen_frame, text="Generate Passwords", 
            command=self.generate_passwords).grid(row=2, column=0, columnspan=4, padx=5, pady=5)
        
        # Password Display Frame
        self.display_frame = ttk.LabelFrame(master, text="Generated Passwords")
        self.display_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Passwords Listbox
        self.passwords_list = tk.Listbox(self.display_frame, width=70, height=10)
        self.passwords_list.pack(padx=5, pady=5, fill='both', expand=True)
        
        # Password Actions Frame
        self.actions_frame = ttk.Frame(master)
        self.actions_frame.pack(padx=10, pady=10)
        
        # Copy Button
        ttk.Button(self.actions_frame, text="Copy Selected", 
            command=self.copy_selected).pack(side=tk.LEFT, padx=5)
        
        # Save Button
        ttk.Button(self.actions_frame, text="Save Passwords", 
            command=self.save_passwords).pack(side=tk.LEFT, padx=5)
        
        # Password Strength Frame
        self.strength_frame = ttk.LabelFrame(master, text="Password Strength")
        self.strength_frame.pack(padx=10, pady=10, fill='x')
        
        # Strength Label
        self.strength_label = ttk.Label(self.strength_frame, text="Strength: N/A")
        self.strength_label.pack(padx=5, pady=5)
    
    def generate_passwords(self):
        """Generate passwords based on user inputs"""
        try:
            # Get parameters
            length = int(self.length_entry.get())
            count = int(self.count_entry.get())
            
            # Generate passwords
            passwords = self.generator.generate_multiple_passwords(
                count=count,
                length=length,
                use_lowercase=bool(self.use_lowercase.get()),
                use_uppercase=bool(self.use_uppercase.get()),
                use_digits=bool(self.use_digits.get()),
                use_special=bool(self.use_special.get())
            )
            
            # Clear previous passwords
            self.passwords_list.delete(0, tk.END)
            
            # Add new passwords
            for pwd in passwords:
                self.passwords_list.insert(tk.END, pwd)
                
            # Update strength for first password
            if passwords:
                strength = self.generator.check_password_strength(passwords[0])
                self.strength_label.config(text=f"Strength: {strength}")
        
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
    
    def copy_selected(self):
        """Copy selected password to clipboard"""
        try:
            selection = self.passwords_list.curselection()
            if selection:
                password = self.passwords_list.get(selection[0])
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
            else:
                messagebox.showwarning("Selection", "Please select a password to copy")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def save_passwords(self):
        """Save generated passwords to a file"""
        try:
            # Get all passwords
            passwords = list(self.passwords_list.get(0, tk.END))
            
            if passwords:
                # Open save dialog
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )
                
                if filename:
                    with open(filename, 'w') as f:
                        for pwd in passwords:
                            f.write(pwd + '\n')
                    
                    messagebox.showinfo("Saved", f"Passwords saved to {filename}")
            else:
                messagebox.showwarning("No Passwords", "Generate passwords first!")
        
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

def main():
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()