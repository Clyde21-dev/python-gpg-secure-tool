import subprocess
import datetime

# Log function for saving actions
def log_action(action):
    with open("log.txt", "a") as log:
        log.write(f"{datetime.datetime.now()} - {action}\n")

# Generate new PGP key
def generate_key():
    print("\n=== Generate New PGP Key Pair ===")
    name = input("Enter your full name: ")
    email = input("Enter your email: ")
    passphrase = input("Enter a secure passphrase: ")

    cmd = ["gpg", "--batch", "--gen-key"]
    input_data = f"Key-Type: RSA\nKey-Length: 2048\nName-Real: {name}\nName-Email: {email}\nPassphrase: {passphrase}\nExpire-Date: 0\n"

    result = subprocess.run(cmd, input=input_data, text=True, capture_output=True)

    if result.returncode == 0:
        print("PGP key successfully generated!")
        log_action("Generated new PGP key.")
    else:
        print("Error generating key:", result.stderr)
        log_action("Failed key generation: " + result.stderr)

# Export public key
def export_public_key():
    email = input("Enter your email (used in key generation): ")
    filename = input("Enter filename to export public key (e.g., public_key.asc): ")

    cmd = ["gpg", "--armor", "--output", filename, "--export", email]
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode == 0:
        print(f"Public key exported to {filename} successfully!")
        log_action(f"Exported public key to {filename}.")
    else:
        print("Error exporting public key:", result.stderr)
        log_action("Failed to export public key: " + result.stderr.decode())

# Import public key from file
def import_public_key():
    filename = input("Enter filename of public key to import: ")

    cmd = ["gpg", "--import", filename]
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode == 0:
        print("Public key imported successfully!")
        log_action(f"Imported public key from {filename}.")
    else:
        print("Error importing public key:", result.stderr)
        log_action("Failed to import public key: " + result.stderr.decode())

# Encrypt a file
def encrypt_file():
    recipient_email = input("Recipient's email: ")
    file_to_encrypt = input("Filename to encrypt: ")
    encrypted_filename = file_to_encrypt + ".gpg"

    cmd = ["gpg", "--armor", "--encrypt", "--recipient", recipient_email, "--output", encrypted_filename, file_to_encrypt]
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode == 0:
        print(f"File encrypted successfully as {encrypted_filename}")
        log_action(f"Encrypted {file_to_encrypt} for {recipient_email}")
    else:
        print("Error encrypting file:", result.stderr)
        log_action("Encryption failed: " + result.stderr.decode())

# Decrypt a file
def decrypt_file():
    encrypted_filename = input("Encrypted filename to decrypt: ")
    decrypted_filename = encrypted_filename.replace(".gpg", "")

    cmd = ["gpg", "--output", decrypted_filename, "--decrypt", encrypted_filename]
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode == 0:
        print(f"File decrypted successfully as {decrypted_filename}")
        log_action(f"Decrypted {encrypted_filename}")
    else:
        print("Error decrypting file:", result.stderr)
        log_action("Decryption failed: " + result.stderr.decode())

# Sign a file
def sign_file():
    file_to_sign = input("Filename to sign: ")
    signed_filename = file_to_sign + ".sig"

    cmd = ["gpg", "--output", signed_filename, "--armor", "--detach-sign", file_to_sign]
    result = subprocess.run(cmd, capture_output=True)

    if result.returncode == 0:
        print(f"File signed successfully as {signed_filename}")
        log_action(f"Signed {file_to_sign}")
    else:
        print("Error signing file:", result.stderr)
        log_action("Signing failed: " + result.stderr.decode())

# Verify a signed file
def verify_signature():
    signature_file = input("Signature filename (.sig file): ")
    original_file = input("Original filename to verify: ")

    cmd = ["gpg", "--verify", signature_file, original_file]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("Signature is valid.")
        log_action(f"Verified signature for {original_file}")
    else:
        print("Signature verification failed:", result.stderr)
        log_action("Signature verification failed: " + result.stderr)

# Interactive menu
def main_menu():
    while True:
        print("\n=== Secure Email System using GPG ===")
        print("1. Generate PGP Key Pair")
        print("2. Export Public Key")
        print("3. Import Public Key")
        print("4. Encrypt a File")
        print("5. Decrypt a File")
        print("6. Sign a File")
        print("7. Verify Signature")
        print("8. Exit")

        choice = input("Choose an option (1-8): ")

        if choice == "1": generate_key()
        elif choice == "2": export_public_key()
        elif choice == "3": import_public_key()
        elif choice == "4": encrypt_file()
        elif choice == "5": decrypt_file()
        elif choice == "6": sign_file()
        elif choice == "7": verify_signature()
        elif choice == "8": break
        else: print("Invalid choice, try again.")

if __name__ == "__main__":
    main_menu()
