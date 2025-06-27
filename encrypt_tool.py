"""
Secure File Encryptor and Directory Hasher with GUI (PyQt5)

Features:
- Encrypt/decrypt files or directories with AES-256-GCM (password-based key derivation with PBKDF2)
- Scan directories recursively and compute SHA-256 hashes of all files
- Built-in multi-threading to avoid UI blocking
- Cross-platform compatible (Windows, Linux)
- UI with two tabs: Encryption/Decryption and Directory Hash Scanner
- Confirmations for overwriting files and bulk operations
- Preserves original file timestamps (creation and modification)
- Thread-safe signals for GUI updates and error reporting
- Clean and user-friendly interface with appropriate sizing and fonts
"""

import sys
import os
import hashlib
import traceback
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit, QTextEdit,
    QFileDialog, QHBoxLayout, QVBoxLayout, QMessageBox, QSizePolicy,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QAbstractItemView, QMenu, QAction
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# === Cryptographic utilities ===

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure 32-byte AES key from password and salt using PBKDF2 SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypts data with AES-256-GCM; returns bytes: salt(16) + iv(12) + tag(16) + ciphertext."""
    from os import urandom
    salt = urandom(16)
    iv = urandom(12)
    key = derive_key(password, salt)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return salt + iv + tag + ciphertext

def decrypt_bytes(enc_data: bytes, password: str) -> bytes:
    """Decrypts data encrypted by encrypt_bytes."""
    salt = enc_data[:16]
    iv = enc_data[16:28]
    tag = enc_data[28:44]
    ciphertext = enc_data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# === File utilities ===

def read_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()

def write_file_preserve_timestamps(file_path: str, data: bytes):
    """Write data overwriting the file and restore original atime/mtime."""
    if os.path.exists(file_path):
        stat = os.stat(file_path)
        atime, mtime = stat.st_atime, stat.st_mtime
    else:
        atime = mtime = time.time()

    with open(file_path, 'wb') as f:
        f.write(data)

    os.utime(file_path, (atime, mtime))

# === GUI Utility Functions ===

def create_label(text: str, bold=False, size=11):
    label = QLabel(text)
    font = QFont("Segoe UI", size)
    font.setBold(bold)
    label.setFont(font)
    return label

def create_line_edit(password=False) -> QLineEdit:
    le = QLineEdit()
    le.setFont(QFont("Segoe UI", 11))
    le.setFixedHeight(30)
    if password:
        le.setEchoMode(QLineEdit.Password)
    return le

def create_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setFont(QFont("Segoe UI", 11))
    btn.setFixedHeight(36)
    btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    btn.setCursor(Qt.PointingHandCursor)
    return btn

def show_message(parent, title: str, message: str, icon=QMessageBox.Information):
    msg_box = QMessageBox(parent)
    msg_box.setWindowTitle(title)
    msg_box.setIcon(icon)
    msg_box.setText(message)
    msg_box.exec_()

# === Worker Threads ===

class CryptoWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    prompt_overwrite = pyqtSignal(str, name='promptOverwrite')
    # The thread will emit prompt_overwrite with a file path and expects a response to be set in a dictionary:
    prompt_responses = {}

    def __init__(self, operation, path, password):
        super().__init__()
        self.operation = operation # "encrypt" or "decrypt"
        self.path = path
        self.password = password
        self.stop_requested = False

    def run(self):
        try:
            if os.path.isdir(self.path):
                total_files, errors = self.process_directory(self.path)
                msg = f"{self.operation.capitalize()} completed on {total_files} files."
                if errors:
                    msg += f" {len(errors)} files failed."
                self.finished.emit(msg)
            else:
                if not self.process_single_file(self.path):
                    self.finished.emit("Operation cancelled by user.")
                    return
                self.finished.emit(f"{self.operation.capitalize()} completed.")
        except Exception as ex:
            self.error.emit(f"Error: {ex}\n{traceback.format_exc()}")

    def process_directory(self, dir_path):
        files_processed = 0
        errors = []
        for root, _, files in os.walk(dir_path):
            for f in files:
                if self.stop_requested:
                    return files_processed, errors
                file_path = os.path.join(root, f)
                try:
                    if not self.process_single_file(file_path):
                        # User cancelled during overwrite prompt
                        self.stop_requested = True
                        return files_processed, errors
                    files_processed += 1
                except Exception as ex:
                    errors.append(f"{file_path}: {ex}")
        return files_processed, errors

    def process_single_file(self, file_path) -> bool:
        """Return False if user cancels overwrite."""
        data = read_file(file_path)
        output_data = None

        if self.operation == 'encrypt':
            output_data = encrypt_bytes(data, self.password)
        else:
            output_data = decrypt_bytes(data, self.password)

        # Before overwrite, prompt for confirmation (only if file exists - always true here)
        # We check if file exists, it does, so ask user in main thread.
        # Use signal-slot for communication.

        # Prepare synchronization via dictionary and event
        # The key will be file_path, value True (overwrite) or False (skip)

        self.prompt_responses[file_path] = None
        self.prompt_overwrite.emit(file_path)

        # Wait loop: busy wait for response with timeout to avoid deadlock. Better approach would be to use QEventLoop but keeping simple.
        import time
        waited = 0
        while self.prompt_responses[file_path] is None:
            time.sleep(0.05)
            waited += 0.05
            if waited > 60:
                # Timeout - assume cancel
                return False

        if self.prompt_responses[file_path] is False:
            # User cancelled overwrite on this file - skip processing it
            return True  # consider skip but continue

        # Proceed to overwrite file
        write_file_preserve_timestamps(file_path, output_data)
        return True

class DirectoryHashWorker(QThread):
    file_hashed = pyqtSignal(str, str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, dir_path):
        super().__init__()
        self.dir_path = dir_path
        self._running = True

    def run(self):
        try:
            for root, _, files in os.walk(self.dir_path):
                if not self._running:
                    break
                for f in files:
                    if not self._running:
                        break
                    fpath = os.path.join(root, f)
                    try:
                        h = self.sha256_file(fpath)
                    except Exception:
                        h = "ERROR"
                    self.file_hashed.emit(fpath, h)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def sha256_file(self, file_path) -> str:
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha.update(chunk)
        return sha.hexdigest()

    def stop(self):
        self._running = False

# === UI: Encryption/Decryption Tab ===

def setup_encryption_tab():
    widget = QWidget()
    layout = QVBoxLayout()

    lbl_title = create_label("File Encryption / Decryption Tool", bold=True, size=18)
    lbl_title.setAlignment(Qt.AlignCenter)
    layout.addWidget(lbl_title)
    layout.addSpacing(12)

    # File/dir selection
    hl_path = QHBoxLayout()
    lbl_path = create_label("File or Directory:", bold=True)
    le_path = QLineEdit()
    le_path.setReadOnly(True)
    le_path.setFixedHeight(30)
    btn_browse = create_button("Browse")
    btn_browse.setMaximumWidth(140)
    hl_path.addWidget(lbl_path, 1)
    hl_path.addWidget(le_path, 6)
    hl_path.addWidget(btn_browse, 1)
    layout.addLayout(hl_path)
    layout.addSpacing(8)

    # Password input
    hl_pwd = QHBoxLayout()
    lbl_pwd = create_label("Password:", bold=True)
    le_pwd = create_line_edit(password=True)
    hl_pwd.addWidget(lbl_pwd, 1)
    hl_pwd.addWidget(le_pwd, 6)
    layout.addLayout(hl_pwd)
    layout.addSpacing(8)

    # Confirm password for encryption only
    hl_pwd_confirm = QHBoxLayout()
    lbl_confirm = create_label("Confirm Password (encryption only):", bold=True)
    le_confirm = create_line_edit(password=True)
    hl_pwd_confirm.addWidget(lbl_confirm, 1)
    hl_pwd_confirm.addWidget(le_confirm, 6)
    layout.addLayout(hl_pwd_confirm)
    layout.addSpacing(15)

    # Buttons Encrypt and Decrypt
    hl_buttons = QHBoxLayout()
    btn_encrypt = create_button("Encrypt")
    btn_decrypt = create_button("Decrypt")
    hl_buttons.addStretch(1)
    hl_buttons.addWidget(btn_encrypt, 1)
    hl_buttons.addSpacing(20)
    hl_buttons.addWidget(btn_decrypt, 1)
    hl_buttons.addStretch(1)
    layout.addLayout(hl_buttons)
    layout.addSpacing(15)

    # Log area
    lbl_log = create_label("Log:")
    te_log = QTextEdit()
    te_log.setReadOnly(True)
    te_log.setFixedHeight(120)
    layout.addWidget(lbl_log)
    layout.addWidget(te_log)

    widget.setLayout(layout)
    return {
        "widget": widget,
        "line_edit_path": le_path,
        "btn_browse": btn_browse,
        "line_edit_password": le_pwd,
        "line_edit_confirm": le_confirm,
        "btn_encrypt": btn_encrypt,
        "btn_decrypt": btn_decrypt,
        "text_log": te_log,
    }

def setup_encryption_logic(ui):
    crypto_worker = None

    def browse_path():
        path = QFileDialog.getExistingDirectory(ui["widget"], "Select Directory (or Cancel to select File)")
        if not path:
            path, _ = QFileDialog.getOpenFileName(ui["widget"], "Select File")
        if path:
            ui["line_edit_path"].setText(path)
            log(ui["text_log"], f"Selected path:\n{path}")

    def validate_inputs(path, pwd, pwd_confirm, op):
        if not path:
            show_message(ui["widget"], "Error", "Please select a file or directory.")
            return False
        if not os.path.exists(path):
            show_message(ui["widget"], "Error", "Selected path does not exist.")
            return False
        if not pwd:
            show_message(ui["widget"], "Error", "Password cannot be empty.")
            return False
        if op == "encrypt" and pwd != pwd_confirm:
            show_message(ui["widget"], "Error", "Passwords do not match.")
            return False

        count_text = f'Folder:\n{path}' if os.path.isdir(path) else f'File:\n{path}'

        reply = QMessageBox.question(
            ui["widget"],
            f"Confirm {op.title()}",
            f"Are you sure you want to {op} the following?\n\n{count_text}\n\nThis will overwrite existing files!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return reply == QMessageBox.Yes

    def on_prompt_overwrite(file_path):
        # Called from worker thread; must notify main thread and wait for response
        # Uses Qt signal-slot with event loop-like wait in worker
        # We execute a dialog in main thread and update shared dict before continuing worker

        # We use QMetaObject.invokeMethod or direct emission with blocking queued connection alternative
        # We'll use a synchronous approach with QEventLoop

        # Use an attribute dictionary to store user responses
        from PyQt5.QtCore import QEventLoop, QMetaObject, Q_ARG, Qt

        response = {}

        def ask_user():
            msg = QMessageBox(ui["widget"])
            msg.setWindowTitle("Overwrite Confirmation")
            msg.setText(f"File:\n{file_path}\n\nAlready exists. Overwrite?")
            msg.setIcon(QMessageBox.Warning)
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            result = msg.exec_()
            response["answer"] = (result == QMessageBox.Yes)
            loop.quit()

        loop = QEventLoop()
        QMetaObject.invokeMethod(ui["widget"], ask_user, Qt.QueuedConnection)
        loop.exec_()

        return response.get("answer", False)

    def process_response(file_path):
        # Called by worker thread to block until user responds
        answer = on_prompt_overwrite(file_path)
        crypto_worker.prompt_responses[file_path] = answer
        return answer

    def run_crypto_worker(operation):
        nonlocal crypto_worker
        path = ui["line_edit_path"].text().strip()
        pwd = ui["line_edit_password"].text()
        conf = ui["line_edit_confirm"].text()
        if not validate_inputs(path, pwd, conf, operation):
            return
        crypto_worker = CryptoWorker(operation, path, pwd)
        crypto_worker.prompt_overwrite.connect(lambda fp: process_response(fp))
        crypto_worker.finished.connect(lambda msg: on_worker_finished(msg))
        crypto_worker.error.connect(lambda err: on_worker_error(err))

        ui["btn_encrypt"].setEnabled(False)
        ui["btn_decrypt"].setEnabled(False)
        crypto_worker.start()
        log(ui["text_log"], f"Started {operation} operation on:\n{path}")

    def on_worker_finished(msg):
        log(ui["text_log"], "✔ " + msg)
        show_message(ui["widget"], "Success", msg)
        ui["btn_encrypt"].setEnabled(True)
        ui["btn_decrypt"].setEnabled(True)

    def on_worker_error(msg):
        log(ui["text_log"], "❌ " + msg)
        show_message(ui["widget"], "Error", msg)
        ui["btn_encrypt"].setEnabled(True)
        ui["btn_decrypt"].setEnabled(True)

    ui["btn_browse"].clicked.connect(browse_path)
    ui["btn_encrypt"].clicked.connect(lambda: run_crypto_worker("encrypt"))
    ui["btn_decrypt"].clicked.connect(lambda: run_crypto_worker("decrypt"))

# === Directory Hash Scanner Tab ===

def setup_hash_tab():
    widget = QWidget()
    layout = QVBoxLayout()

    hl_path = QHBoxLayout()
    lbl_path = create_label("Directory to Scan:", bold=True)
    le_path = QLineEdit()
    le_path.setReadOnly(True)
    le_path.setFixedHeight(28)
    btn_browse = create_button("Browse")
    btn_browse.setMaximumWidth(140)
    hl_path.addWidget(lbl_path)
    hl_path.addWidget(le_path, 1)
    hl_path.addWidget(btn_browse)
    layout.addLayout(hl_path)
    layout.addSpacing(8)

    hl_buttons = QHBoxLayout()
    btn_start = create_button("Start Scan")
    btn_stop = create_button("Stop Scan")
    btn_stop.setEnabled(False)
    hl_buttons.addStretch(1)
    hl_buttons.addWidget(btn_start)
    hl_buttons.addWidget(btn_stop)
    hl_buttons.addStretch(1)
    layout.addLayout(hl_buttons)

    tree_widget = QTreeWidget()
    tree_widget.setHeaderLabels(["File Path", "SHA-256 Hash"])
    tree_widget.header().setSectionResizeMode(0, Qt.Stretch)
    tree_widget.header().setSectionResizeMode(1, Qt.ResizeToContents)
    tree_widget.setSelectionMode(QAbstractItemView.SingleSelection)
    layout.addWidget(tree_widget)

    widget.setLayout(layout)
    return {
        "widget": widget,
        "line_edit_path": le_path,
        "btn_browse": btn_browse,
        "btn_start": btn_start,
        "btn_stop": btn_stop,
        "tree_widget": tree_widget,
    }

def setup_hash_tab_logic(ui):
    scan_thread = {"thread": None}

    def browse_directory():
        path = QFileDialog.getExistingDirectory(ui["widget"], "Select Directory")
        if path:
            ui["line_edit_path"].setText(path)
            ui["tree_widget"].clear()

    def add_item(file_path, hash_value):
        item = QTreeWidgetItem([file_path, hash_value])
        ui["tree_widget"].addTopLevelItem(item)

    def scan_finished():
        ui["btn_start"].setEnabled(True)
        ui["btn_stop"].setEnabled(False)
        show_message(ui["widget"], "Scan Finished", "Directory hash scan completed successfully.")

    def scan_error(error_msg):
        ui["btn_start"].setEnabled(True)
        ui["btn_stop"].setEnabled(False)
        show_message(ui["widget"], "Error", f"Error during scan:\n{error_msg}")

    def start_scan():
        dir_path = ui["line_edit_path"].text().strip()
        if not dir_path or not os.path.isdir(dir_path):
            show_message(ui["widget"], "Input Error", "Please select a valid directory first.")
            return

        reply = QMessageBox.question(
            ui["widget"],
            "Confirm Directory Scan",
            f"Are you sure you want to scan and hash all files under:\n\n{dir_path}?\n\nThis operation may take some time.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        ui["tree_widget"].clear()
        ui["btn_start"].setEnabled(False)
        ui["btn_stop"].setEnabled(True)

        thread = DirectoryHashWorker(dir_path)
        scan_thread["thread"] = thread
        thread.file_hashed.connect(add_item)
        thread.finished.connect(scan_finished)
        thread.error.connect(scan_error)
        thread.start()

    def stop_scan():
        thread = scan_thread.get("thread")
        if thread and thread.isRunning():
            thread.stop()
            thread.wait()
        ui["btn_start"].setEnabled(True)
        ui["btn_stop"].setEnabled(False)
        show_message(ui["widget"], "Scan Stopped", "Directory scan was stopped by the user.")

    def context_menu(point):
        item = ui["tree_widget"].itemAt(point)
        if not item:
            return
        menu = QMenu(ui["tree_widget"])
        copy_action = QAction("Copy SHA-256 Hash")
        def copy_hash():
            QApplication.clipboard().setText(item.text(1))
        copy_action.triggered.connect(copy_hash)
        menu.addAction(copy_action)
        menu.exec_(ui["tree_widget"].mapToGlobal(point))

    ui["btn_browse"].clicked.connect(browse_directory)
    ui["btn_start"].clicked.connect(start_scan)
    ui["btn_stop"].clicked.connect(stop_scan)
    ui["tree_widget"].setContextMenuPolicy(Qt.CustomContextMenu)
    ui["tree_widget"].customContextMenuRequested.connect(context_menu)

# === Simple logger ===

def log(text_widget: QTextEdit, message: str):
    text_widget.append(message)
    text_widget.verticalScrollBar().setValue(text_widget.verticalScrollBar().maximum())

# === Main ===

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    tab_widget = QTabWidget()
    tab_widget.setWindowTitle("Secure File Encryptor & Directory Hasher")
    tab_widget.resize(700, 520)
    tab_widget.setMinimumSize(660, 480)

    # Setup Encryption Tab
    encrypt_ui = setup_encryption_tab()
    setup_encryption_logic(encrypt_ui)
    tab_widget.addTab(encrypt_ui["widget"], "Encrypt / Decrypt")

    # Setup Scan Tab
    scan_ui = setup_hash_tab()
    setup_hash_tab_logic(scan_ui)
    tab_widget.addTab(scan_ui["widget"], "Directory Hash Scanner")

    tab_widget.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
