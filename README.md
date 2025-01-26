# HackBlitz

The Secure Notes Application allows users to store and manage notes securely. Notes can be encrypted with a password using AES encryption (CBC mode) to protect sensitive information. The encryption key is derived from the user's password using PBKDF2 with SHA-256, ensuring strong protection. Notes are saved in a JSON file, with each note either encrypted or stored in plaintext if no password is set.

The user can add a note by providing a title, content, and optionally a password. If a password is provided, the content is encrypted; otherwise, it is stored in plain text. When viewing a note, users must enter the password if the note is protected. The application then decrypts and displays the content.

This app ensures that sensitive information remains secure through encryption while offering an easy-to-use interface for managing notes.
