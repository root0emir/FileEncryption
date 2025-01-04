import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QFileDialog, QLabel, QLineEdit
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet

# root0emir 

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Dosya Şifreleme")
        self.setGeometry(100, 100, 600, 500)

        self.key = None  # Şifreleme anahtarı
        self.selected_file = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

    
        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setStyleSheet("background-color: #2c3e50; color: white; font-family: Arial, sans-serif; font-size: 12px;")
        layout.addWidget(self.log_text_edit)

        
        self.key_input_label = QLabel("Şifreleme Anahtarını Girin (isteğe bağlı):")
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Anahtar (varsa)...")
        layout.addWidget(self.key_input_label)
        layout.addWidget(self.key_input)

        # Dosya Seçme ve Şifreleme Butonları
        self.select_button = QPushButton("Dosya Seç", self)
        self.select_button.setStyleSheet("background-color: #2980b9; color: white; font-size: 14px;")
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)

        self.encrypt_button = QPushButton("Dosyayı Şifrele", self)
        self.encrypt_button.setStyleSheet("background-color: #27ae60; color: white; font-size: 14px;")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Dosya Şifresini Çöz", self)
        self.decrypt_button.setStyleSheet("background-color: #e74c3c; color: white; font-size: 14px;")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.result_label = QLabel(self)
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def log(self, message):
        """Log mesajlarını arayüze yansıtır"""
        self.log_text_edit.append(message)

    def generate_key(self):
        """Yeni bir şifreleme anahtarı üretir"""
        self.key = Fernet.generate_key()
        return self.key

    def select_file(self):
        """Dosya seçme penceresini açar"""
        file_dialog = QFileDialog(self)
        self.selected_file = file_dialog.getOpenFileName()[0]
        if self.selected_file:
            self.log(f"Seçilen dosya: {self.selected_file}")

    def encrypt_file(self):
        """Dosyayı şifreler"""
        if not self.selected_file:
            self.log("Lütfen bir dosya seçin.")
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

            # Anahtarı ekranda göster
            self.log(f"Şifreleme Anahtarı: {self.key.decode()}")

            self.log(f"Dosya başarıyla şifrelendi: {encrypted_file_path}")
            self.result_label.setText(f"Dosya başarıyla şifrelendi: {encrypted_file_path}")
        except Exception as e:
            self.log(f"Dosya şifrelenemedi: {e}")

    def decrypt_file(self):
        """Şifreli dosyanın şifresini çözer"""
        if not self.selected_file:
            self.log("Lütfen bir dosya seçin.")
            return

        if self.key_input.text():  # Kullanıcı anahtar girdiyse
            self.key = self.key_input.text().encode()
        else:
            self.log("Lütfen geçerli bir şifreleme anahtarı girin.")
            return

        # Şifreli dosyanın .enc uzantısı ile bitip bitmediğini kontrol ediyoruz
        if not self.selected_file.endswith(".enc"):
            self.log("Lütfen şifreli bir dosya seçin (.enc uzantılı).")
            return

        try:
         
            with open(self.selected_file, "rb") as f:
                encrypted_data = f.read()

            cipher_suite = Fernet(self.key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            # Şifresi çözülen dosyanın orijinal ismini al (uzantı değişmesin)
            decrypted_file_path = self.selected_file[:-4]  # .enc kısmını çıkarıyoruz

            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)

            self.log(f"Dosya başarıyla şifresi çözüldü: {decrypted_file_path}")
            self.result_label.setText(f"Dosya başarıyla şifresi çözüldü: {decrypted_file_path}")
        except Exception as e:
            self.log(f"Dosya şifresi çözülemedi: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())
