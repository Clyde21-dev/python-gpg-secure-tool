Secure Email System using GPG (Python CLI)

This is a Python command-line mini project that helps you manage secure email operations using GPG/PGP. You can generate PGP keys, export/import keys, encrypt/decrypt files, and sign/verify files—all from a simple interactive menu.

Features:

- Generate new PGP key pairs
- Export your public key to a file
- Import someone else’s public key from a file
- Encrypt files for a recipient
- Decrypt encrypted files sent to you
- Digitally sign files
- Verify signatures on files
- Logs all actions to log.txt with timestamps

Requirements:

- Python 3.x
- GPG (GNU Privacy Guard) installed and available in your system PATH

Installation:

1. Clone or download this repository
2. Make sure you have Python 3 and GPG installed

On Ubuntu/Debian:
    sudo apt-get install python3 gnupg

Usage:

Run the script from your terminal:
    python3 secure_email_gpg.py

Follow the on-screen menu:
    1. Generate PGP Key Pair
    2. Export Public Key
    3. Import Public Key
    4. Encrypt a File
    5. Decrypt a File
    6. Sign a File
    7. Verify Signature
    8. Exit

Each option will prompt you for necessary info (like email, filenames, etc).

Example Workflow:

- To encrypt a file, make sure you’ve imported the recipient’s public key.
- To decrypt a file, you need the corresponding private key.
- To sign a file, just select the file and follow the prompt.
- To verify a signature, you’ll need both the signature and the original file.

Log:

All actions (key generation, encryption, signing, etc.) are saved to log.txt in the current directory with a timestamp.

Security Note:

Never share your private key or passphrase.
Always use a strong passphrase for key generation.

Troubleshooting:

- If you see an error about GPG, make sure it’s installed and in your system PATH.
- If you get permission errors, check that you have write access to the project folder.

License:

Open source – free to use for educational or personal purposes.