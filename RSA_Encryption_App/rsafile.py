import customtkinter as ctk
from tkinter import messagebox, filedialog
import webbrowser
import json
import os
import datetime
import random
from sympy import randprime
from PIL import Image, ImageTk

# Setup Theme
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")

# Modern UI Constants
FONT_FAMILY = "Segoe UI"
PRIMARY_COLOR = "#2196F3"
SECONDARY_COLOR = "#1976D2"
ACCENT_COLOR = "#FF4081"
BACKGROUND_COLOR = "#F5F5F5"
CARD_COLOR = "#FFFFFF"
TEXT_COLOR = "#333333"
SUBTEXT_COLOR = "#666666"

# Font Sizes
TITLE_FONT = (FONT_FAMILY, 24, "bold")
HEADER_FONT = (FONT_FAMILY, 18, "bold")
BODY_FONT = (FONT_FAMILY, 14)
SMALL_FONT = (FONT_FAMILY, 12)

# Spacing
PADDING = 20
INNER_PADDING = 10
BUTTON_PADDING = 5

# ====== RSA Utility Functions ======
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x, y = x2 - temp1 * x1, d - temp1 * y1
        x2, x1, d, y1 = x1, x, y1, y
    if temp_phi == 1:
        return d + phi

def generate_key_pair(bits):
    p = randprime(2**(bits//2-1), 2**(bits//2))
    q = randprime(2**(bits//2-1), 2**(bits//2))
    while p == q:
        q = randprime(2**(bits//2-1), 2**(bits//2))
    n = p * q
    phi = (p-1)*(q-1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(msg, key):
    e, n = key
    return [pow(ord(char), e, n) for char in msg]

def decrypt(cipher, key):
    d, n = key
    return ''.join([chr(pow(c, d, n)) for c in cipher])

def save_to_file(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, "w") as f:
            f.write(data)

def share_email(data):
    webbrowser.open(f"mailto:?subject=Secure Cipher Scribe&body={data}")

def save_history(entry):
    if not os.path.exists("history.json"):
        with open("history.json", "w") as f:
            json.dump([], f)
    with open("history.json", "r+") as f:
        history = json.load(f)
        history.append(entry)
        f.seek(0)
        json.dump(history, f, indent=4)
        f.truncate()

def load_history():
    if not os.path.exists("history.json"):
        return []
    with open("history.json", "r") as f:
        return json.load(f)

def clear_history():
    with open("history.json", "w") as f:
        json.dump([], f)

def download_history():
    history = load_history()
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, "w") as f:
            for entry in history:
                f.write(json.dumps(entry, indent=4))
                f.write("\\n\\n")

# ====== Authentication Helper Functions ======
def signup_user(email, password):
    if not os.path.exists("users.json"):
        with open("users.json", "w") as f:
            json.dump([], f)
    with open("users.json", "r+") as f:
        users = json.load(f)
        for user in users:
            if user["email"] == email:
                messagebox.showerror("Error", "User already exists.")
                return
        users.append({"email": email, "password": password})
        f.seek(0)
        json.dump(users, f, indent=4)
        f.truncate()

def login_user(email, password, login_win):
    if not os.path.exists("users.json"):
        messagebox.showerror("Error", "No users found. Please sign up first.")
        return
    with open("users.json", "r") as f:
        users = json.load(f)
        for user in users:
            if user["email"] == email and user["password"] == password:
                login_win.destroy()
                build_main_app()
                return
    messagebox.showerror("Error", "Invalid email or password.")

# ====== GUI Windows ======
def show_login_window():
    login_win = ctk.CTk()
    login_win.title("Login - Secure Cipher Scribe")
    login_win.geometry("500x600")
    login_win.configure(fg_color=BACKGROUND_COLOR)
    
    # Main container
    container = ctk.CTkFrame(login_win, fg_color=BACKGROUND_COLOR)
    container.pack(expand=True, fill="both", padx=PADDING, pady=PADDING)
    
    # Title
    title_frame = ctk.CTkFrame(container, fg_color=BACKGROUND_COLOR)
    title_frame.pack(pady=PADDING*2)
    ctk.CTkLabel(title_frame, 
                text="Secure Cipher Scribe", 
                font=TITLE_FONT,
                text_color=PRIMARY_COLOR).pack()
    ctk.CTkLabel(title_frame, 
                text="Secure your messages with RSA encryption", 
                font=SMALL_FONT,
                text_color=SUBTEXT_COLOR).pack(pady=5)
    
    # Login form
    form_frame = ctk.CTkFrame(container, fg_color=CARD_COLOR, corner_radius=15)
    form_frame.pack(expand=True, fill="both", padx=PADDING, pady=PADDING)
    
    ctk.CTkLabel(form_frame, 
                text="Welcome Back", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=PADDING)
    
    # Email field
    email_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    email_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(email_frame, 
                text="Email", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    email_entry = ctk.CTkEntry(email_frame, 
                              placeholder_text="Enter your email",
                              font=BODY_FONT,
                              height=40)
    email_entry.pack(fill="x", pady=5)
    
    # Password field
    password_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    password_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(password_frame, 
                text="Password", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    password_entry = ctk.CTkEntry(password_frame, 
                                 placeholder_text="Enter your password",
                                 font=BODY_FONT,
                                 height=40,
                                 show="•")
    password_entry.pack(fill="x", pady=5)
    
    # Login button
    login_button = ctk.CTkButton(form_frame,
                               text="Login",
                               font=BODY_FONT,
                               height=45,
                               fg_color=PRIMARY_COLOR,
                               hover_color=SECONDARY_COLOR,
                               command=lambda: login_user(email_entry.get(), password_entry.get(), login_win))
    login_button.pack(fill="x", padx=PADDING, pady=PADDING)
    
    # Sign up link
    signup_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    signup_frame.pack(pady=INNER_PADDING)
    ctk.CTkLabel(signup_frame, 
                text="Don't have an account?", 
                font=SMALL_FONT,
                text_color=SUBTEXT_COLOR).pack(side="left")
    signup_button = ctk.CTkButton(signup_frame,
                                text="Sign Up",
                                font=SMALL_FONT,
                                fg_color=CARD_COLOR,
                                hover_color=CARD_COLOR,
                                text_color=PRIMARY_COLOR,
                                command=lambda: show_signup_window(login_win))
    signup_button.pack(side="left", padx=5)
    
    login_win.mainloop()

def show_signup_window(login_win):
    login_win.destroy()
    signup_win = ctk.CTk()
    signup_win.title("Sign Up - Secure Cipher Scribe")
    signup_win.geometry("500x700")
    signup_win.configure(fg_color=BACKGROUND_COLOR)
    
    # Main container
    container = ctk.CTkFrame(signup_win, fg_color=BACKGROUND_COLOR)
    container.pack(expand=True, fill="both", padx=PADDING, pady=PADDING)
    
    # Title
    title_frame = ctk.CTkFrame(container, fg_color=BACKGROUND_COLOR)
    title_frame.pack(pady=PADDING*2)
    ctk.CTkLabel(title_frame, 
                text="Secure Cipher Scribe", 
                font=TITLE_FONT,
                text_color=PRIMARY_COLOR).pack()
    ctk.CTkLabel(title_frame, 
                text="Create your secure account", 
                font=SMALL_FONT,
                text_color=SUBTEXT_COLOR).pack(pady=5)
    
    # Signup form
    form_frame = ctk.CTkFrame(container, fg_color=CARD_COLOR, corner_radius=15)
    form_frame.pack(expand=True, fill="both", padx=PADDING, pady=PADDING)
    
    ctk.CTkLabel(form_frame, 
                text="Create Account", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=PADDING)
    
    # Email field
    email_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    email_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(email_frame, 
                text="Email", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    email_entry = ctk.CTkEntry(email_frame, 
                              placeholder_text="Enter your email",
                              font=BODY_FONT,
                              height=40)
    email_entry.pack(fill="x", pady=5)
    
    # Password field
    password_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    password_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(password_frame, 
                text="Password", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    password_entry = ctk.CTkEntry(password_frame, 
                                 placeholder_text="Create a password",
                                 font=BODY_FONT,
                                 height=40,
                                 show="•")
    password_entry.pack(fill="x", pady=5)
    
    # Confirm Password field
    confirm_password_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    confirm_password_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(confirm_password_frame, 
                text="Confirm Password", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    confirm_password_entry = ctk.CTkEntry(confirm_password_frame, 
                                        placeholder_text="Confirm your password",
                                        font=BODY_FONT,
                                        height=40,
                                        show="•")
    confirm_password_entry.pack(fill="x", pady=5)
    
    def create_account():
        email = email_entry.get()
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if "@" not in email:
            messagebox.showerror("Error", "Invalid email. Please include '@' in your email address.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters.")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        signup_user(email, password)
        signup_win.destroy()
        show_login_window()

    # Create Account button
    create_button = ctk.CTkButton(form_frame,
                                text="Create Account",
                                font=BODY_FONT,
                                height=45,
                                fg_color=PRIMARY_COLOR,
                                hover_color=SECONDARY_COLOR,
                                command=create_account)
    create_button.pack(fill="x", padx=PADDING, pady=PADDING)
    
    # Login link
    login_frame = ctk.CTkFrame(form_frame, fg_color=CARD_COLOR)
    login_frame.pack(pady=INNER_PADDING)
    ctk.CTkLabel(login_frame, 
                text="Already have an account?", 
                font=SMALL_FONT,
                text_color=SUBTEXT_COLOR).pack(side="left")
    login_button = ctk.CTkButton(login_frame,
                               text="Login",
                               font=SMALL_FONT,
                               fg_color=CARD_COLOR,
                               hover_color=CARD_COLOR,
                               text_color=PRIMARY_COLOR,
                               command=lambda: [signup_win.destroy(), show_login_window()])
    login_button.pack(side="left", padx=5)
    
    signup_win.mainloop()

# ====== Main App Window ======
def build_main_app():
    global app, main_frame
    app = ctk.CTk()
    app.title("Secure Cipher Scribe")
    app.geometry("1400x800")
    app.configure(fg_color=BACKGROUND_COLOR)
    app.grid_rowconfigure(1, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Header
    header = ctk.CTkFrame(app, height=70, corner_radius=0, fg_color=CARD_COLOR)
    header.grid(row=0, column=0, columnspan=2, sticky="ew")
    header.grid_columnconfigure(1, weight=1)
    
    # Logo and title
    title_frame = ctk.CTkFrame(header, fg_color=CARD_COLOR)
    title_frame.grid(row=0, column=0, padx=PADDING, pady=10, sticky="w")
    ctk.CTkLabel(title_frame, 
                text="Secure Cipher Scribe", 
                font=TITLE_FONT,
                text_color=PRIMARY_COLOR).pack(side="left")
    ctk.CTkLabel(title_frame, 
                text="RSA Encryption Tool", 
                font=SMALL_FONT,
                text_color=SUBTEXT_COLOR).pack(side="left", padx=10)

    # Sidebar
    sidebar = ctk.CTkFrame(app, width=250, corner_radius=0, fg_color=CARD_COLOR)
    sidebar.grid(row=1, column=0, sticky="ns")
    sidebar.grid_rowconfigure(2, weight=1)
    
    # Navigation menu
    menu_frame = ctk.CTkFrame(sidebar, fg_color=CARD_COLOR)
    menu_frame.pack(pady=PADDING*2)
    
    ctk.CTkLabel(menu_frame, 
                text="Navigation", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=10)
    
    home_button = ctk.CTkButton(menu_frame,
                              text="Home",
                              font=BODY_FONT,
                              height=45,
                              fg_color=CARD_COLOR,
                              hover_color=BACKGROUND_COLOR,
                              text_color=TEXT_COLOR,
                              anchor="w",
                              command=lambda: show_home(main_frame))
    home_button.pack(fill="x", pady=5)
    
    history_button = ctk.CTkButton(menu_frame,
                                 text="History",
                                 font=BODY_FONT,
                                 height=45,
                                 fg_color=CARD_COLOR,
                                 hover_color=BACKGROUND_COLOR,
                                 text_color=TEXT_COLOR,
                                 anchor="w",
                                 command=lambda: show_history(main_frame))
    history_button.pack(fill="x", pady=5)

    # Main content area
    main_frame = ctk.CTkFrame(app, corner_radius=0, fg_color=BACKGROUND_COLOR)
    main_frame.grid(row=1, column=1, sticky="nsew", padx=PADDING, pady=PADDING)
    main_frame.grid_columnconfigure((0, 1, 2), weight=1)
    main_frame.grid_rowconfigure(0, weight=1)

    show_home(main_frame)
    app.mainloop()

def show_home(main):
    for widget in main.winfo_children():
        widget.destroy()

    main.grid_rowconfigure(0, weight=1)
    main.grid_columnconfigure((0, 1, 2), weight=1)

    # Card 1 Key Generation
    card1 = ctk.CTkFrame(main, corner_radius=15, fg_color=CARD_COLOR)
    card1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    card1.grid_columnconfigure(0, weight=1)
    
    ctk.CTkLabel(card1, 
                text="Key Generation", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=PADDING)
    
    bit_frame = ctk.CTkFrame(card1, fg_color=CARD_COLOR)
    bit_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(bit_frame, 
                text="Key Size", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    bit_option = ctk.CTkOptionMenu(bit_frame, 
                                  values=["1024", "2048"],
                                  font=BODY_FONT,
                                  height=40)
    bit_option.pack(fill="x", pady=5)
    
    key_frame = ctk.CTkFrame(card1, fg_color=CARD_COLOR)
    key_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(key_frame, 
                text="Public Key", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    pub_text = ctk.CTkTextbox(key_frame, 
                             height=40,
                             font=BODY_FONT)
    pub_text.pack(fill="x", pady=5)
    
    ctk.CTkLabel(key_frame, 
                text="Private Key", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x", pady=(10, 0))
    priv_text = ctk.CTkTextbox(key_frame, 
                              height=40,
                              font=BODY_FONT)
    priv_text.pack(fill="x", pady=5)
    
    button_frame = ctk.CTkFrame(card1, fg_color=CARD_COLOR)
    button_frame.pack(fill="x", padx=PADDING, pady=PADDING)
    ctk.CTkButton(button_frame,
                 text="Copy Public Key",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: app.clipboard_append(pub_text.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Copy Private Key",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: app.clipboard_append(priv_text.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Generate Keys",
                 font=BODY_FONT,
                 height=45,
                 fg_color=ACCENT_COLOR,
                 hover_color="#F50057",
                 command=lambda: handle_keygen(bit_option, pub_text, priv_text)).pack(fill="x", pady=10)

    # Card 2 Encrypt
    card2 = ctk.CTkFrame(main, corner_radius=15, fg_color=CARD_COLOR)
    card2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
    card2.grid_columnconfigure(0, weight=1)
    
    ctk.CTkLabel(card2, 
                text="Encrypt Message", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=PADDING)
    
    message_frame = ctk.CTkFrame(card2, fg_color=CARD_COLOR)
    message_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(message_frame, 
                text="Message", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    entry_message = ctk.CTkEntry(message_frame, 
                                placeholder_text="Enter message to encrypt",
                                font=BODY_FONT,
                                height=40)
    entry_message.pack(fill="x", pady=5)
    
    pubkey_frame = ctk.CTkFrame(card2, fg_color=CARD_COLOR)
    pubkey_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(pubkey_frame, 
                text="Public Key", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    entry_pubkey = ctk.CTkEntry(pubkey_frame, 
                               placeholder_text="Enter public key (e,n)",
                               font=BODY_FONT,
                               height=40)
    entry_pubkey.pack(fill="x", pady=5)
    
    output_frame = ctk.CTkFrame(card2, fg_color=CARD_COLOR)
    output_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(output_frame, 
                text="Encrypted Message", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    output_cipher = ctk.CTkTextbox(output_frame, 
                                  height=60,
                                  font=BODY_FONT)
    output_cipher.pack(fill="x", pady=5)
    
    button_frame = ctk.CTkFrame(card2, fg_color=CARD_COLOR)
    button_frame.pack(fill="x", padx=PADDING, pady=PADDING)
    ctk.CTkButton(button_frame,
                 text="Paste Public Key",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: entry_pubkey.insert(0, pub_text.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Encrypt",
                 font=BODY_FONT,
                 height=45,
                 fg_color=ACCENT_COLOR,
                 hover_color="#F50057",
                 command=lambda: handle_encrypt(entry_message, entry_pubkey, output_cipher, pub_text)).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Save Cipher",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: save_to_file(output_cipher.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Share Cipher by Email",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: share_email(output_cipher.get("1.0", "end").strip())).pack(fill="x", pady=5)

    # Card 3 Decrypt
    card3 = ctk.CTkFrame(main, corner_radius=15, fg_color=CARD_COLOR)
    card3.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
    card3.grid_columnconfigure(0, weight=1)
    
    ctk.CTkLabel(card3, 
                text="Decrypt Message", 
                font=HEADER_FONT,
                text_color=TEXT_COLOR).pack(pady=PADDING)
    
    cipher_frame = ctk.CTkFrame(card3, fg_color=CARD_COLOR)
    cipher_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(cipher_frame, 
                text="Ciphertext", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    entry_cipher = ctk.CTkEntry(cipher_frame, 
                               placeholder_text="Enter ciphertext to decrypt",
                               font=BODY_FONT,
                               height=40)
    entry_cipher.pack(fill="x", pady=5)
    
    privkey_frame = ctk.CTkFrame(card3, fg_color=CARD_COLOR)
    privkey_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(privkey_frame, 
                text="Private Key", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    entry_privkey = ctk.CTkEntry(privkey_frame, 
                                placeholder_text="Enter private key (d,n)",
                                font=BODY_FONT,
                                height=40)
    entry_privkey.pack(fill="x", pady=5)
    
    output_frame = ctk.CTkFrame(card3, fg_color=CARD_COLOR)
    output_frame.pack(fill="x", padx=PADDING, pady=INNER_PADDING)
    ctk.CTkLabel(output_frame, 
                text="Decrypted Message", 
                font=BODY_FONT,
                text_color=TEXT_COLOR,
                anchor="w").pack(fill="x")
    output_plain = ctk.CTkTextbox(output_frame, 
                                 height=60,
                                 font=BODY_FONT)
    output_plain.pack(fill="x", pady=5)
    
    button_frame = ctk.CTkFrame(card3, fg_color=CARD_COLOR)
    button_frame.pack(fill="x", padx=PADDING, pady=PADDING)
    ctk.CTkButton(button_frame,
                 text="Paste Private Key",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: entry_privkey.insert(0, priv_text.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Decrypt",
                 font=BODY_FONT,
                 height=45,
                 fg_color=ACCENT_COLOR,
                 hover_color="#F50057",
                 command=lambda: handle_decrypt(entry_cipher, entry_privkey, output_plain)).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Save Plain Text",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: save_to_file(output_plain.get("1.0", "end").strip())).pack(fill="x", pady=5)
    ctk.CTkButton(button_frame,
                 text="Share Plain Text by Email",
                 font=BODY_FONT,
                 height=40,
                 fg_color=PRIMARY_COLOR,
                 hover_color=SECONDARY_COLOR,
                 command=lambda: share_email(output_plain.get("1.0", "end").strip())).pack(fill="x", pady=5)

def show_history(main):
    for widget in main.winfo_children():
        widget.destroy()

    main.grid_rowconfigure(0, weight=1)
    main.grid_columnconfigure(0, weight=1)

    hist_text = ctk.CTkTextbox(main)
    hist_text.pack(expand=True, fill="both")

    history = load_history()
    for entry in history:
        hist_text.insert("end", json.dumps(entry, indent=4))
        hist_text.insert("end", "\\n\\n")

    ctk.CTkButton(main, text="Clear History", command=lambda: [clear_history(), show_history(main)]).pack(pady=5)
    ctk.CTkButton(main, text="Download History", command=download_history).pack(pady=5)

# ====== Button Handlers ======
def handle_keygen(bit_option, pub_text, priv_text):
    bits = int(bit_option.get())
    pub, priv = generate_key_pair(bits)
    pub_text.delete("1.0", "end")
    priv_text.delete("1.0", "end")
    pub_text.insert("end", str(pub))
    priv_text.insert("end", str(priv))

def handle_encrypt(entry_message, entry_pubkey, output_cipher, pub_text):
    try:
        key = eval(entry_pubkey.get()) if entry_pubkey.get() else eval(pub_text.get("1.0", "end").strip())
        msg = entry_message.get()
        cipher = encrypt(msg, key)
        output_cipher.delete("1.0", "end")
        output_cipher.insert("end", str(cipher))
        save_history({"type": "encryption", "input": msg, "cipher": cipher, "pubkey": key, "timestamp": str(datetime.datetime.now())})
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_decrypt(entry_cipher, entry_privkey, output_plain):
    try:
        cipher = eval(entry_cipher.get())
        key = eval(entry_privkey.get())
        plain = decrypt(cipher, key)
        output_plain.delete("1.0", "end")
        output_plain.insert("end", plain)
        save_history({"type": "decryption", "cipher": cipher, "plain": plain, "privkey": key, "timestamp": str(datetime.datetime.now())})
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ====== Start ======
show_login_window()
