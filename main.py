import os
import sys
from PyPDF2 import PdfReader, PdfWriter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_pdf_with_password(input_path, output_path, password):
    """Encrypt PDF file with password protection"""
    try:
        # Read the PDF
        reader = PdfReader(input_path)
        writer = PdfWriter()
        
        # Add all pages to writer
        for page in reader.pages:
            writer.add_page(page)
        
        # Encrypt with password
        writer.encrypt(password)
        
        # Write encrypted PDF
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        
        print(f"PDF successfully encrypted with password protection: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error encrypting PDF: {e}")
        return False

def encrypt_file_with_fernet(input_path, output_path, password):
    """Encrypt entire PDF file using Fernet encryption"""
    try:
        # Generate key from password
        key, salt = generate_key_from_password(password)
        fernet = Fernet(key)
        
        # Read file data
        with open(input_path, 'rb') as file:
            file_data = file.read()
        
        # Encrypt data
        encrypted_data = fernet.encrypt(file_data)
        
        # Write encrypted file with salt prepended
        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_data)
        
        print(f"File successfully encrypted: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error encrypting file: {e}")
        return False

def decrypt_file_with_fernet(input_path, output_path, password):
    """Decrypt file encrypted with Fernet"""
    try:
        # Read encrypted file
        with open(input_path, 'rb') as encrypted_file:
            file_data = encrypted_file.read()
        
        # Extract salt and encrypted data
        salt = file_data[:16]
        encrypted_data = file_data[16:]
        
        # Generate key from password and salt
        key, _ = generate_key_from_password(password, salt)
        fernet = Fernet(key)
        
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted file
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        print(f"File successfully decrypted: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error decrypting file: {e}")
        return False

def main():
    """Main function with user interface"""
    print("PDF Encryption Tool")
    print("=" * 30)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt PDF with password protection (PDF native)")
        print("2. Encrypt PDF file with strong encryption (Fernet)")
        print("3. Decrypt Fernet-encrypted file")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1' or choice == '2':
            input_path = input("Enter path to PDF file: ").strip()
            if not os.path.exists(input_path):
                print("File not found!")
                continue
            
            overwrite = input("Overwrite original file? (y/n): ").strip().lower()
            
            if overwrite == 'y':
                output_path = input_path
            else:
                output_folder = input("Enter folder path to save encrypted file: ").strip()
                if not os.path.exists(output_folder):
                    print("Folder does not exist!")
                    continue
                # Create output filename with "_encrypted" suffix
                base_name = os.path.basename(input_path)
                name, ext = os.path.splitext(base_name)
                output_path = os.path.join(output_folder, name + "_encrypted" + ext)
            
            password = input("Enter password for encryption: ")
            
            if choice == '1':
                encrypt_pdf_with_password(input_path, output_path, password)
            else:
                encrypt_file_with_fernet(input_path, output_path, password)
        
        elif choice == '3':
            input_path = input("Enter path to encrypted file: ").strip()
            if not os.path.exists(input_path):
                print("File not found!")
                continue
            
            output_path = input("Enter output path for decrypted file: ").strip()
            password = input("Enter password for decryption: ")
            
            decrypt_file_with_fernet(input_path, output_path, password)
        
        elif choice == '4':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
