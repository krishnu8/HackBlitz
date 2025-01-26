from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import json

# File to store encrypted notes
NOTES_FILE = "secure_notes.json"

# Helper function to derive encryption key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a note
def encrypt_note(note: str, password: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(note.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "salt": urlsafe_b64encode(salt).decode(),
        "iv": urlsafe_b64encode(iv).decode(),
        "ciphertext": urlsafe_b64encode(ciphertext).decode()
    }

# Function to decrypt a note
def decrypt_note(encrypted_note: dict, password: str) -> str:
    salt = urlsafe_b64decode(encrypted_note["salt"])
    iv = urlsafe_b64decode(encrypted_note["iv"])
    ciphertext = urlsafe_b64decode(encrypted_note["ciphertext"])

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    note = unpadder.update(padded_data) + unpadder.finalize()

    return note.decode()

# Function to load notes from a file
def load_notes() -> dict:
    if not os.path.exists(NOTES_FILE):
        return {}
    with open(NOTES_FILE, "r") as file:
        return json.load(file)

# Function to save notes to a file
def save_notes(notes: dict):
    with open(NOTES_FILE, "w") as file:
        json.dump(notes, file)

# Add a new note
def add_note():
    title = input("Enter note title: ")
    content = input("Enter note content: ")
    password = input("Enter a password (leave blank for no password): ")
    
    notes = load_notes()
    if password.strip():
        encrypted_note = encrypt_note(content, password)
        encrypted_note["protected"] = True
    else:
        encrypted_note = {"protected": False, "content": content}
    notes[title] = encrypted_note
    save_notes(notes)
    print("Note added successfully.")

# View a note
def view_note():
    notes = load_notes()
    if not notes:
        print("No notes available.")
        return

    print("Available notes:")
    for index, title in enumerate(notes.keys(), start=1):
        print(f"{index}. {title}")

    try:
        choice = int(input("\nEnter the number of the note you want to view: "))
        selected_title = list(notes.keys())[choice - 1]
        encrypted_note = notes[selected_title]

        password = input("Enter the password (if any): ")
        if encrypted_note.get("protected", False):
            try:
                decrypted_note = decrypt_note(encrypted_note, password)
                print(f"Content of '{selected_title}':\n{decrypted_note}")
                action = input("Choose an action: [edit/delete]: ").strip().lower()
                if action == "edit":
                    new_content = input("Enter new content: ")
                    encrypted_note = encrypt_note(new_content, password) if password else {"protected": False, "content": new_content}
                    notes[selected_title] = encrypted_note
                    save_notes(notes)
                    print("Note updated successfully.")
                elif action == "delete":
                    delete_note(selected_title)
                else:
                    print("Invalid option.")
            except Exception:
                print("Failed to decrypt the note. Incorrect password.")
        else:
            print(f"Content of '{selected_title}':\n{encrypted_note['content']}")
            print("1:Edit \n 2:Delete")
            action = input("Choose an action:").strip().lower()
            if action == "1":
                new_content = input("Enter new content: ")
                encrypted_note = {"protected": False, "content": new_content}
                notes[selected_title] = encrypted_note
                save_notes(notes)
                print("Note updated successfully.")
            elif action == "2":
                delete_note(selected_title)
            else:
                print("Invalid option.")
    except (ValueError, IndexError):
        print("Invalid choice. Please select a valid note number.")

# Delete a note
def delete_note(title: str):
    notes = load_notes()
    if title in notes:
        del notes[title]
        save_notes(notes)
        print("Note deleted successfully.")
    else:
        print("Note not found.")

# Main menu
def main():
    while True:
        print("\nSecure Notes App")
        print("1. Add Note")
        print("2. View Note")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_note()
        elif choice == "2":
            view_note()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
