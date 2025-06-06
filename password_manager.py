#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PythCrypt - Gestor de Contraseñas Personal
Aplicación de escritorio moderna y segura para gestionar contraseñas
"""

import sys
import json
import os
import secrets
import string
import sqlite3
from datetime import datetime, timedelta
import threading
import base64
from pathlib import Path

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QTableWidget, QTableWidgetItem, 
                           QPushButton, QLineEdit, QLabel, QDialog, 
                           QFormLayout, QCheckBox, QSpinBox, QMessageBox,
                           QHeaderView, QFrame, QSplitter, QGroupBox,
                           QTextEdit, QDialogButtonBox, QInputDialog,
                           QStyleOptionButton, QStyle)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QIcon, QPixmap, QPainter, QColor, QPalette

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class DatabaseManager:
    """Maneja el almacenamiento cifrado de contraseñas"""
    
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.cipher_suite = None
        self.setup_database()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Deriva una clave de cifrado desde la contraseña maestra"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def setup_database(self):
        """Inicializa la base de datos SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabla de configuración (para almacenar el salt)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Tabla de contraseñas cifradas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def initialize_encryption(self, master_password: str) -> bool:
        """Inicializa el cifrado con la contraseña maestra"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verificar si ya existe un salt
        cursor.execute("SELECT value FROM config WHERE key = 'salt'")
        salt_row = cursor.fetchone()
        
        if salt_row:
            # Base de datos existente
            salt = base64.urlsafe_b64decode(salt_row[0])
            key = self.derive_key(master_password, salt)
            self.cipher_suite = Fernet(key)
            
            # Verificar contraseña intentando descifrar un valor de prueba
            cursor.execute("SELECT value FROM config WHERE key = 'test'")
            test_row = cursor.fetchone()
            
            if test_row:
                try:
                    self.cipher_suite.decrypt(test_row[0].encode())
                    conn.close()
                    return True
                except:
                    conn.close()
                    return False
            else:
                # Primera vez con esta contraseña, crear valor de prueba
                test_value = self.cipher_suite.encrypt(b"test_value")
                cursor.execute("INSERT INTO config (key, value) VALUES (?, ?)",
                             ("test", test_value.decode()))
                conn.commit()
                conn.close()
                return True
        else:
            # Nueva base de datos
            salt = os.urandom(16)
            key = self.derive_key(master_password, salt)
            self.cipher_suite = Fernet(key)
            
            # Guardar salt y valor de prueba
            cursor.execute("INSERT INTO config (key, value) VALUES (?, ?)",
                         ("salt", base64.urlsafe_b64encode(salt).decode()))
            test_value = self.cipher_suite.encrypt(b"test_value")
            cursor.execute("INSERT INTO config (key, value) VALUES (?, ?)",
                         ("test", test_value.decode()))
            
            conn.commit()
            conn.close()
            return True
    
    def add_password(self, service: str, username: str, password: str, notes: str = ""):
        """Agrega una nueva contraseña cifrada"""
        if not self.cipher_suite:
            raise Exception("Base de datos no inicializada")
        
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO passwords (service, username, password, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (service, username, encrypted_password, notes, now, now))
        
        conn.commit()
        conn.close()
    
    def get_all_passwords(self):
        """Obtiene todas las contraseñas (cifradas)"""
        if not self.cipher_suite:
            raise Exception("Base de datos no inicializada")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, service, username, password, notes, created_at FROM passwords")
        rows = cursor.fetchall()
        conn.close()
        
        return rows
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """Descifra una contraseña"""
        if not self.cipher_suite:
            raise Exception("Base de datos no inicializada")
        
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()
    
    def update_password(self, password_id: int, service: str, username: str, password: str, notes: str = ""):
        """Actualiza una contraseña existente"""
        if not self.cipher_suite:
            raise Exception("Base de datos no inicializada")
        
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE passwords SET service=?, username=?, password=?, notes=?, updated_at=?
            WHERE id=?
        ''', (service, username, encrypted_password, notes, now, password_id))
        
        conn.commit()
        conn.close()
    
    def delete_password(self, password_id: int):
        """Elimina una contraseña"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM passwords WHERE id=?", (password_id,))
        
        conn.commit()
        conn.close()


class PasswordGenerator:
    """Generador de contraseñas seguras"""
    
    @staticmethod
    def generate_password(length=16, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_symbols=True, exclude_ambiguous=True):
        """Genera una contraseña aleatoria segura"""
        if not any([use_uppercase, use_lowercase, use_digits, use_symbols]):
            raise ValueError("Debe seleccionar al menos un tipo de carácter")
        
        characters = ""
        
        if use_lowercase:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = chars.replace('l', '').replace('o', '')
            characters += chars
        
        if use_uppercase:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = chars.replace('I', '').replace('O', '')
            characters += chars
        
        if use_digits:
            chars = string.digits
            if exclude_ambiguous:
                chars = chars.replace('0', '').replace('1', '')
            characters += chars
        
        if use_symbols:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            characters += chars
        
        # Generar contraseña asegurando que tenga al menos un carácter de cada tipo seleccionado
        password = []
        
        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Completar el resto de la longitud
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))
        
        # Mezclar la contraseña
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


class ClipboardManager:
    """Maneja el copiado temporal al portapapeles"""
    
    def __init__(self):
        self.clipboard = QApplication.clipboard()
        self.timer = QTimer()
        self.timer.timeout.connect(self.clear_clipboard)
        self.original_text = ""
    
    def copy_temporarily(self, text: str, duration: int = 15000):
        """Copia texto al portapapeles por un tiempo determinado"""
        self.original_text = self.clipboard.text()
        self.clipboard.setText(text)
        
        if self.timer.isActive():
            self.timer.stop()
        
        self.timer.start(duration)  # duración en milisegundos
    
    def clear_clipboard(self):
        """Limpia el portapapeles"""
        current_text = self.clipboard.text()
        # Solo limpiar si el contenido no ha cambiado (usuario no copió otra cosa)
        if current_text != self.original_text:
            self.clipboard.clear()
        self.timer.stop()

class PasswordGeneratorDialog(QDialog):
    """Diálogo para generar contraseñas"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generador de Contraseñas")
        self.setFixedSize(500, 450)
        self.generated_password = ""
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Configuración de la contraseña
        config_group = QGroupBox("Configuración")
        config_layout = QFormLayout()
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(26)
        config_layout.addRow("Longitud:", self.length_spin)
        config_layout.setContentsMargins(20, 20, 20, 20)

        self.uppercase_check = QCheckBox("Mayúsculas (A-Z)")
        self.uppercase_check.setChecked(True)
        config_layout.addRow(self.uppercase_check)
        
        self.lowercase_check = QCheckBox("Minúsculas (a-z)")
        self.lowercase_check.setChecked(True)
        config_layout.addRow(self.lowercase_check)
        
        self.digits_check = QCheckBox("Números (0-9)")
        self.digits_check.setChecked(True)
        config_layout.addRow(self.digits_check)
        
        self.symbols_check = QCheckBox("Símbolos (!@#$%)")
        self.symbols_check.setChecked(True)
        config_layout.addRow(self.symbols_check)
        
        self.exclude_ambiguous_check = QCheckBox("Excluir caracteres ambiguos (0, O, l, I)")
        self.exclude_ambiguous_check.setChecked(True)
        config_layout.addRow(self.exclude_ambiguous_check)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Botón generar
        self.generate_btn = QPushButton("🎲 Generar Contraseña")
        self.generate_btn.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_btn)
        
        # Campo de resultado
        result_group = QGroupBox("Contraseña Generada")
        result_layout = QVBoxLayout()
        
        self.password_text = QTextEdit()
        self.password_text.setMaximumHeight(60)
        self.password_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.password_text)
        
        button_layout = QHBoxLayout()
        self.copy_btn = QPushButton("📋 Copiar")
        self.copy_btn.clicked.connect(self.copy_password)
        self.copy_btn.setEnabled(False)
        button_layout.addWidget(self.copy_btn)
        
        self.use_btn = QPushButton("Aceptar")
        self.use_btn.clicked.connect(self.accept)
        self.use_btn.setEnabled(False)
        button_layout.addWidget(self.use_btn)
        
        result_layout.addLayout(button_layout)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        # Botones del diálogo
        button_box = QDialogButtonBox(QDialogButtonBox.Cancel)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
        # Generar contraseña inicial
        self.generate_password()
    
    def generate_password(self):
        """Genera una nueva contraseña"""
        try:
            password = PasswordGenerator.generate_password(
                length=self.length_spin.value(),
                use_uppercase=self.uppercase_check.isChecked(),
                use_lowercase=self.lowercase_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_symbols=self.symbols_check.isChecked(),
                exclude_ambiguous=self.exclude_ambiguous_check.isChecked()
            )
            self.generated_password = password
            self.password_text.setText(password)
            self.copy_btn.setEnabled(True)
            self.use_btn.setEnabled(True)
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))
    
    def copy_password(self):
        """Copia la contraseña al portapapeles"""
        if self.generated_password:
            QApplication.clipboard().setText(self.generated_password)
            self.copy_btn.setText("✅ Copiado!")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText("📋 Copiar"))
    
    def apply_styles(self):
        """Aplica estilos al diálogo"""
        self.setStyleSheet("""
            QDialog {
                background-color: #f8f9fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #dee2e6;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #495057;
            }
            QPushButton {
                background-color: #343a40;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #495057;
            }
            QPushButton:pressed {
                background-color: #212529;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
            QTextEdit {
                border: 2px solid #dee2e6;
                border-radius: 6px;
                padding: 8px;
                background-color: white;
            }
        """)


class AddPasswordDialog(QDialog):
    """Diálogo para agregar/editar contraseñas"""
    
    def __init__(self, parent=None, edit_data=None):
        super().__init__(parent)
        self.edit_data = edit_data
        self.setWindowTitle("Editar Contraseña" if edit_data else "Agregar Contraseña")
        self.setFixedSize(450, 300)
        self.setup_ui()
        self.apply_styles()
        
        if edit_data:
            self.load_edit_data()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Formulario
        form_layout = QFormLayout()
        
        self.service_edit = QLineEdit()
        self.service_edit.setPlaceholderText("ej: Gmail, Facebook, GitHub...")
        self.service_edit.setMinimumHeight(35)
        form_layout.addRow("Servicio:", self.service_edit)
        
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Usuario o email...")
        self.username_edit.setMinimumHeight(35)
        form_layout.addRow("Usuario:", self.username_edit)
        
        # Layout para contraseña con botón generador
        password_layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Contraseña...")
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setMinimumHeight(20)
        password_layout.addWidget(self.password_edit)
        
        self.show_password_btn = QPushButton("👁")
        self.show_password_btn.setFixedSize(20, 35)
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setStyleSheet("padding: 0px; margin: 0px;")
        self.show_password_btn.toggled.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_btn)

        self.generate_password_btn = QPushButton("🎲")
        self.generate_password_btn.setFixedSize(20, 35)
        self.generate_password_btn.setStyleSheet("padding: 0px; margin: 0px;")
        self.generate_password_btn.setToolTip("Generar contraseña")
        self.generate_password_btn.clicked.connect(self.open_password_generator)
        password_layout.addWidget(self.generate_password_btn)

        
        password_widget = QWidget()
        password_widget.setLayout(password_layout)
        form_layout.addRow("Contraseña:", password_widget)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(80)
        self.notes_edit.setPlaceholderText("Notas adicionales (opcional)...")
        form_layout.addRow("Notas:", self.notes_edit)
        
        layout.addLayout(form_layout)
        
        # Botones
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("💾 Guardar")
        self.save_btn.clicked.connect(self.save_password)
        self.save_btn.setMinimumHeight(40)
        button_layout.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("❌ Cancelar")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumHeight(40)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def load_edit_data(self):
        """Carga los datos para edición"""
        if self.edit_data:
            self.service_edit.setText(self.edit_data.get('service', ''))
            self.username_edit.setText(self.edit_data.get('username', ''))
            self.password_edit.setText(self.edit_data.get('password', ''))
            self.notes_edit.setText(self.edit_data.get('notes', ''))
    
    def toggle_password_visibility(self, checked):
        """Alterna la visibilidad de la contraseña"""
        if checked:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText("🙈")
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText("👁")
    
    def open_password_generator(self):
        """Abre el generador de contraseñas"""
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.password_edit.setText(dialog.generated_password)
    
    def save_password(self):
        """Valida y guarda la contraseña"""
        service = self.service_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        notes = self.notes_edit.toPlainText().strip()
        
        if not service or not username or not password:
            QMessageBox.warning(self, "Error", "Servicio, usuario y contraseña son obligatorios.")
            return
        
        self.result = {
            'service': service,
            'username': username,
            'password': password,
            'notes': notes
        }
        
        self.accept()
    
    def apply_styles(self):
        """Aplica estilos al diálogo"""
        self.setStyleSheet("""
            QDialog {
                background-color: #f8f9fa;
            }
            QLineEdit, QTextEdit {
                border: 2px solid #dee2e6;
                border-radius: 6px;
                padding: 8px;
                background-color: white;
                font-size: 13px;
                min-height: 20px;
            }
            QLineEdit:focus, QTextEdit:focus {
                border-color: #343a40;
            }
            QPushButton {
                background-color: #343a40;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                min-width: 80px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #495057;
            }
            QPushButton:pressed {
                background-color: #212529;
            }
            QLabel {
                color: #495057;
                font-weight: bold;
                label.setContentsMargins(5, 5, 5, 5)
            }
        """)


class LoginDialog(QDialog):
    """Diálogo de inicio de sesión con contraseña maestra"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pythcrypt - Acceso")
        self.setFixedSize(350, 220)
        self.setModal(True)
        self.master_password = ""
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        layout.setSpacing(15)

        # Logo/Título
        title_label = QLabel("Pythcrypt 🔐")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(title_label)

        subtitle_label = QLabel("Ingresa tu contraseña maestra")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #6c757d; font-size: 13px;")
        layout.addWidget(subtitle_label)

        # Campo de contraseña
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Contraseña maestra")
        layout.addWidget(self.password_input)

        # Botones
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        self.ok_button = QPushButton("Ingresar")
        self.ok_button.clicked.connect(self.handle_login)  # ← Manejo correcto

        self.ok_button.setDefault(True)

        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def handle_login(self):
        """Guarda la contraseña ingresada y cierra el diálogo"""
        self.master_password = self.password_input.text()
        self.accept()

    def apply_styles(self):
        """Aplica estilos personalizados al diálogo"""
        self.setStyleSheet("""
            QDialog {
                background-color: #f8f9fa;
                border-radius: 10px;
            }

            QLabel {
                font-family: 'Segoe UI';
                label.setContentsMargins(15, 15, 15, 15)
            }

            QLineEdit {
                padding: 10px;
                border: 1px solid #ced4da;
                border-radius: 5px;
                font-size: 14px;
                background-color: white;
            }

            QPushButton {
                background-color: #007bff;
                color: white;
                font-weight: bold;
                border: none;
                padding: 8px 14px;
                border-radius: 6px;
            }

            QPushButton:hover {
                background-color: #0069d9;
            }

            QPushButton:pressed {
                background-color: #0056b3;
            }
        """)

        


class PasswordManagerWindow(QMainWindow):
    """Ventana principal del gestor de contraseñas"""
    
    def __init__(self):
        super().__init__()
        self.db_manager = DatabaseManager()
        self.clipboard_manager = ClipboardManager()
        self.passwords_data = []
        
        self.setWindowTitle("Pythcrypt 🔐")
        self.setMinimumSize(900, 600)
        self.resize(1100, 700)
        
        # Intentar hacer login
        if not self.login():
            sys.exit()
        
        self.setup_ui()
        self.apply_styles()
        self.load_passwords()
        
        # Centrar ventana
        self.center_window()
    
    def login(self):
        """Maneja el proceso de login"""
        login_dialog = LoginDialog(self)
        
        if login_dialog.exec_() != QDialog.Accepted:
            return False
        
        master_password = login_dialog.master_password
        
        try:
            success = self.db_manager.initialize_encryption(master_password)
            if not success:
                QMessageBox.critical(self, "Error", "Contraseña maestra incorrecta.")
                return self.login()  # Intentar de nuevo
            return True
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al inicializar la base de datos: {str(e)}")
            return False
    
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Barra de herramientas superior
        self.setup_toolbar(main_layout)
        
        # Tabla de contraseñas
        self.setup_password_table(main_layout)
        
        # Barra de estado
        self.statusBar().showMessage("Listo - Base de datos cifrada y segura")
    
    def setup_toolbar(self, parent_layout):
        """Configura la barra de herramientas"""
        toolbar_frame = QFrame()
        toolbar_frame.setFrameStyle(QFrame.StyledPanel)
        toolbar_layout = QHBoxLayout()
        toolbar_frame.setLayout(toolbar_layout)
        
        # Botón agregar
        self.add_btn = QPushButton("➕ Agregar Contraseña")
        self.add_btn.clicked.connect(self.add_password)
        self.add_btn.setMinimumHeight(35)
        toolbar_layout.addWidget(self.add_btn)
        
        # Botón generador
        self.generator_btn = QPushButton("🎲 Generar Contraseña")
        self.generator_btn.clicked.connect(self.open_password_generator)
        self.generator_btn.setMinimumHeight(35)
        toolbar_layout.addWidget(self.generator_btn)
        
        # Espaciador
        toolbar_layout.addStretch()
        
        # Campo de búsqueda

        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar servicio o usuario...")
        self.search_edit.textChanged.connect(self.filter_passwords)
        self.search_edit.setMaximumWidth(250)
        self.search_edit.setMinimumHeight(35)
        toolbar_layout.addWidget(self.search_edit)
        
        # Botón actualizar
        self.refresh_btn = QPushButton("🔄")
        self.refresh_btn.clicked.connect(self.load_passwords)
        self.refresh_btn.setToolTip("Actualizar lista")
        self.refresh_btn.setMinimumSize(40, 40)
        toolbar_layout.addWidget(self.refresh_btn)
        
        parent_layout.addWidget(toolbar_frame)
    
    def setup_password_table(self, parent_layout):
        """Configura la tabla de contraseñas"""
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(6)
        self.password_table.setHorizontalHeaderLabels([
            "Servicio", "Usuario", "Contraseña", "Notas", "Creado", "Acciones"
        ])
        
        # Configurar encabezados
        header = self.password_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Servicio
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Usuario
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Contraseña
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Notas
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Creado

        self.password_table.setColumnWidth(5, 220)
        
        # Configurar tabla
        self.password_table.setAlternatingRowColors(True)
        self.password_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.password_table.setShowGrid(True)
        self.password_table.setGridStyle(Qt.SolidLine)
        self.password_table.setRowHeight(0, 50)  # Altura mínima de filas
        self.password_table.verticalHeader().setDefaultSectionSize(85)
        
        parent_layout.addWidget(self.password_table)
    
    def load_passwords(self):
        """Carga las contraseñas desde la base de datos"""
        try:
            passwords = self.db_manager.get_all_passwords()
            self.passwords_data = passwords
            self.populate_table(passwords)
            self.statusBar().showMessage(f"{len(passwords)} contraseñas cargadas.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al cargar contraseñas: {str(e)}")
    
    def populate_table(self, passwords):
        """Llena la tabla con las contraseñas"""
        self.password_table.setRowCount(len(passwords))
        
        for row, password_data in enumerate(passwords):
            password_id, service, username, encrypted_password, notes, created_at = password_data
            
            # Servicio
            self.password_table.setItem(row, 0, QTableWidgetItem(service))
            
            # Usuario
            self.password_table.setItem(row, 1, QTableWidgetItem(username))
            
            # Contraseña (oculta inicialmente)
            password_item = QTableWidgetItem("••••••••")
            password_item.setData(Qt.UserRole, encrypted_password)  # Guardar contraseña cifrada
            self.password_table.setItem(row, 2, password_item)
            
            # Notas
            notes_display = notes[:30] + "..." if len(notes) > 30 else notes
            self.password_table.setItem(row, 3, QTableWidgetItem(notes_display))
            
            # Fecha de creación
            try:
                created_date = datetime.fromisoformat(created_at).strftime("%d/%m/%Y")
            except:
                created_date = "N/A"
            self.password_table.setItem(row, 4, QTableWidgetItem(created_date))
            
            # Botones de acción
            self.create_action_buttons(row, password_id, encrypted_password)
    
    def create_action_buttons(self, row, password_id, encrypted_password):
        """Crea los botones de acción para cada fila"""
        action_widget = QWidget()
        action_layout = QHBoxLayout()
        action_layout.setContentsMargins(15, 15, 15, 15)
        action_layout.setSpacing(5)
        
        # Botón mostrar/ocultar contraseña
        show_btn = QPushButton("👁")
        show_btn.setMinimumSize(40, 40)
        show_btn.setCheckable(True)
        show_btn.setToolTip("Mostrar/Ocultar contraseña")
        show_btn.toggled.connect(lambda checked, r=row, enc=encrypted_password: 
                               self.toggle_password_visibility(r, enc, checked))
        action_layout.addWidget(show_btn)
        
        # Botón copiar
        copy_btn = QPushButton("📋")
        copy_btn.setMinimumSize(40, 40)
        copy_btn.setToolTip("Copiar contraseña")
        copy_btn.clicked.connect(lambda _, enc=encrypted_password: self.copy_password(enc))
        action_layout.addWidget(copy_btn)
        
        # Botón editar
        edit_btn = QPushButton("✏️")
        edit_btn.setMinimumSize(40, 40)
        edit_btn.setToolTip("Editar")
        edit_btn.clicked.connect(lambda _, pid=password_id: self.edit_password(pid))
        action_layout.addWidget(edit_btn)
        
        # Botón eliminar
        delete_btn = QPushButton("🗑️")
        delete_btn.setMinimumSize(40, 40)
        delete_btn.setToolTip("Eliminar")
        delete_btn.clicked.connect(lambda _, pid=password_id: self.delete_password(pid))
        action_layout.addWidget(delete_btn)
        
        action_widget.setLayout(action_layout)
        self.password_table.setCellWidget(row, 5, action_widget)
    
    def toggle_password_visibility(self, row, encrypted_password, show):
        """Alterna la visibilidad de una contraseña"""
        try:
            if show:
                # Mostrar contraseña real
                real_password = self.db_manager.decrypt_password(encrypted_password)
                self.password_table.item(row, 2).setText(real_password)
            else:
                # Ocultar contraseña
                self.password_table.item(row, 2).setText("••••••••")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error al descifrar contraseña: {str(e)}")
    
    def copy_password(self, encrypted_password):
        """Copia una contraseña al portapapeles temporalmente"""
        try:
            real_password = self.db_manager.decrypt_password(encrypted_password)
            self.clipboard_manager.copy_temporarily(real_password, 15000)  # 15 segundos
            self.statusBar().showMessage("Contraseña copiada al portapapeles (se borrará en 15 segundos)", 3000)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error al copiar contraseña: {str(e)}")
    
    def add_password(self):
        """Abre el diálogo para agregar nueva contraseña"""
        dialog = AddPasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            try:
                self.db_manager.add_password(
                    dialog.result['service'],
                    dialog.result['username'],
                    dialog.result['password'],
                    dialog.result['notes']
                )
                self.load_passwords()
                self.statusBar().showMessage("Contraseña agregada exitosamente", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error al agregar contraseña: {str(e)}")
    
    def edit_password(self, password_id):
        """Edita una contraseña existente"""
        # Buscar los datos de la contraseña
        password_data = None
        for data in self.passwords_data:
            if data[0] == password_id:
                password_data = data
                break
        
        if not password_data:
            QMessageBox.warning(self, "Error", "No se encontró la contraseña.")
            return
        
        # Descifrar la contraseña para mostrarla en el diálogo
        try:
            decrypted_password = self.db_manager.decrypt_password(password_data[3])
            edit_data = {
                'service': password_data[1],
                'username': password_data[2],
                'password': decrypted_password,
                'notes': password_data[4] or ''
            }
            
            dialog = AddPasswordDialog(self, edit_data)
            if dialog.exec_() == QDialog.Accepted:
                self.db_manager.update_password(
                    password_id,
                    dialog.result['service'],
                    dialog.result['username'],
                    dialog.result['password'],
                    dialog.result['notes']
                )
                self.load_passwords()
                self.statusBar().showMessage("Contraseña actualizada exitosamente", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al editar contraseña: {str(e)}")
    
    def delete_password(self, password_id):
        """Elimina una contraseña"""
        reply = QMessageBox.question(
            self,
            "Confirmar eliminación",
            "¿Estás seguro de que quieres eliminar esta contraseña?\n\nEsta acción no se puede deshacer.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                self.db_manager.delete_password(password_id)
                self.load_passwords()
                self.statusBar().showMessage("Contraseña eliminada exitosamente", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error al eliminar contraseña: {str(e)}")
    
    def open_password_generator(self):
        """Abre el generador de contraseñas independiente"""
        dialog = PasswordGeneratorDialog(self)
        dialog.exec_()
    
    def filter_passwords(self, search_text):
        """Filtra las contraseñas basándose en el texto de búsqueda"""
        if not search_text:
            self.populate_table(self.passwords_data)
            return
        
        search_text = search_text.lower()
        filtered_passwords = []
        
        for password_data in self.passwords_data:
            service = password_data[1].lower()
            username = password_data[2].lower()
            
            if search_text in service or search_text in username:
                filtered_passwords.append(password_data)
        
        self.populate_table(filtered_passwords)
        self.statusBar().showMessage(f"Mostrando {len(filtered_passwords)} de {len(self.passwords_data)} contraseñas")
    
    def center_window(self):
        """Centra la ventana en la pantalla"""
        screen = QApplication.desktop().screenGeometry()
        size = self.geometry()
        self.move(
            int((screen.width() - size.width()) / 2),
            int((screen.height() - size.height()) / 2)
        )
    
    def apply_styles(self):
        """Aplica estilos a la ventana principal"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            
            QFrame {
                background-color: white;
                border: none;
                border-radius: 8px;
                padding: 10px;
                margin: 5px;
            }
            
            QPushButton {
                background-color: #343a40;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                min-height: 20px;
                font-size: 13px;
            }
            
            QPushButton:hover {
                background-color: #495057;
            }
            
            QPushButton:pressed {
                background-color: #212529;
            }
            
            QPushButton:checked {
                background-color: #28a745;
            }
            
            QLineEdit {
                border: 2px solid #dee2e6;
                border-radius: 6px;
                padding: 8px;
                background-color: white;
                font-size: 13px;
            }
            
            QLineEdit:focus {
                border-color: #007bff;
            }
            
            QTableWidget {
                gridline-color: #dee2e6;
                background-color: white;
                alternate-background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                font-size: 13px;
            }
            
            QTableWidget::item {
                padding: 12px 8px;
                border-bottom: 1px solid #dee2e6;
            }
            
            QTableWidget::item:selected {
                background-color: #343a40;
                color: white;
            }
        
            
            QStatusBar {
                background-color: #e9ecef;
                border-top: 1px solid #dee2e6;
                padding: 5px;
                color: #495057;
            }
            
            QLabel {
                color: #495057;
                label.setContentsMargins(15, 15, 15, 15)

            }
            
            QMessageBox {
                background-color: #f8f9fa;
            }
        """)
    
    def closeEvent(self, event):
        """Maneja el evento de cierre de la aplicación"""
        reply = QMessageBox.question(
            self,
            "Salir",
            "¿Estás seguro de que quieres salir?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Limpiar el portapapeles antes de salir
            if self.clipboard_manager.timer.isActive():
                self.clipboard_manager.clear_clipboard()
            event.accept()
        else:
            event.ignore()


def main():
    """Función principal"""
    app = QApplication(sys.argv)
    
    # Configurar la aplicación
    app.setApplicationName("Pythcrypt - Gestor de Contraseñas Personal")
    app.setOrganizationName("PasswordManager")
    app.setApplicationVersion("1.0")
    
    # Configurar fuente por defecto
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    # Crear y mostrar la ventana principal
    try:
        window = PasswordManagerWindow()
        window.show()
        
        # Ejecutar la aplicación
        sys.exit(app.exec_())
        
    except Exception as e:
        QMessageBox.critical(None, "Error Fatal", f"Error al iniciar la aplicación:\n{str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

