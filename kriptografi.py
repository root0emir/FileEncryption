import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog, QLabel, QLineEdit
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet

# root0emir 

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("File Encryption")
        self.setGeometry(100, 100, 600, 500)

        self.key = None  # Encryption key
        self.selected_file = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setStyleSheet("background-color: #2c3e50; color: white; font-family: Arial, sans-serif; font-size: 12px;")
        layout.addWidget(self.log_text_edit)

        self.key_input_label = QLabel("Enter Encryption Key (optional):")
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Key (if available)...")
        layout.addWidget(self.key_input_label)
        layout.addWidget(self.key_input)

        self.select_button = QPushButton("Select File", self)
        self.select_button.setStyleSheet("background-color: #2980b9; color: white; font-size: 14px;")
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)

        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.setStyleSheet("background-color: #27ae60; color: white; font-size: 14px;")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.setStyleSheet("background-color: #e74c3c; color: white; font-size: 14px;")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.result_label = QLabel(self)
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def log(self, message):
        """Displays log messages in the UI"""
        self.log_text_edit.append(message)

    def generate_key(self):
        """Generates a new encryption key"""
        self.key = Fernet.generate_key()
        return self.key

    def select_file(self):
        """Opens the file selection dialog"""
        file_dialog = QFileDialog(self)
        self.selected_file = file_dialog.getOpenFileName()[0]
        if self.selected_file:
            self.log(f"Selected file: {self.selected_file}")

    def encrypt_file(self):
        """Encrypts the selected file"""
        if not self.selected_file:
            self.log("Please select a file.")
            return

        if self.key_input.text(): 
            self.key = self.key_input.text().encode()
        else:  
            self.key = self.generate_key()

        try:
            with open(self.selected_file, "rb") as f:
                file_data = f.read()

            cipher_suite = Fernet(self.key)
            encrypted_data = cipher_suite.encrypt(file_data)

            encrypted_file_path = self.selected_file + ".enc"
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_data)

            self.log(f"Encryption Key: {self.key.decode()}")
            self.log(f"File successfully encrypted: {encrypted_file_path}")
            self.result_label.setText(f"File successfully encrypted: {encrypted_file_path}")
        except Exception as e:
            self.log(f"File encryption failed: {e}")

    def decrypt_file(self):
        """Decrypts the selected encrypted file"""
        if not self.selected_file:
            self.log("Please select a file.")
            return

        if self.key_input.text():
            self.key = self.key_input.text().encode()
        else:
            self.log("Please enter a valid encryption key.")
            return

        if not self.selected_file.endswith(".enc"):
            self.log("Please select an encrypted file (.enc extension).")
            return

        try:
            with open(self.selected_file, "rb") as f:
                encrypted_data = f.read()

            cipher_suite = Fernet(self.key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            decrypted_file_path = self.selected_file[:-4]  # Removing .enc extension

            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)

            self.log(f"File successfully decrypted: {decrypted_file_path}")
            self.result_label.setText(f"File successfully decrypted: {decrypted_file_path}")
        except Exception as e:
            self.log(f"File decryption failed: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())
