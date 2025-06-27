import sys
import os
import traceback
import time
import shutil
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit, QTextEdit,
    QFileDialog, QHBoxLayout, QVBoxLayout, QMessageBox, QSizePolicy
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    """通过密码和salt派生AES256密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    """AES256-GCM加密数据，格式salt(16)+iv(12)+tag(16)+密文"""
    from os import urandom

    salt = urandom(16)
    iv = urandom(12)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return salt + iv + tag + ciphertext

def decrypt_data(enc_data: bytes, password: str) -> bytes:
    """AES256-GCM解密数据"""
    salt = enc_data[:16]
    iv = enc_data[16:28]
    tag = enc_data[28:44]
    ciphertext = enc_data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted

def read_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

def write_file_preserve_time(filepath, data):
    """写文件内容，并保持原文件时间不变"""
    # 先备份原时间
    if os.path.exists(filepath):
        stat = os.stat(filepath)
        atime = stat.st_atime
        mtime = stat.st_mtime
    else:
        atime = mtime = time.time()

    # 写入数据（覆盖）
    with open(filepath, 'wb') as f:
        f.write(data)

    # 恢复时间
    os.utime(filepath, (atime, mtime))

def msg_box(parent, title, msg):
    QMessageBox.information(parent, title, msg)

def select_path():
    options = QFileDialog.Options()
    # 先尝试选目录
    path = QFileDialog.getExistingDirectory(None, "Select Directory (or Cancel to choose File)", options=options)
    if not path:
        # 没选目录，选文件
        path, _ = QFileDialog.getOpenFileName(None, "Select File", "", "All Files (*)", options=options)
    return path

class WorkerThread(QThread):
    finished_signal = pyqtSignal(str)  # 成功消息
    error_signal = pyqtSignal(str)     # 错误消息

    def __init__(self, mode, path, password):
        super().__init__()
        self.mode = mode  # 'encrypt' or 'decrypt'
        self.path = path
        self.password = password

    def run(self):
        try:
            if os.path.isdir(self.path):
                count, errors = self.batch_process_dir(self.path)
                msg = f'{self.mode.title()} succeeded on {count} files.'
                if errors:
                    msg += f' {len(errors)} files failed.'
                self.finished_signal.emit(msg)
            else:
                self.process_file(self.path)
                self.finished_signal.emit(f'{self.mode.title()} succeeded.')
        except Exception as e:
            tb = traceback.format_exc()
            self.error_signal.emit(f'Error: {str(e)}\n\nDetails:\n{tb}')

    def batch_process_dir(self, root_path):
        file_count = 0
        errors = []
        for dirpath, _, filenames in os.walk(root_path):
            for fn in filenames:
                fpath = os.path.join(dirpath, fn)
                try:
                    self.process_file(fpath)
                    file_count += 1
                except Exception as e:
                    errors.append(f'{fpath}: {str(e)}')
        return file_count, errors

    def process_file(self, filepath):
        data = read_file(filepath)
        if self.mode == 'encrypt':
            enc = encrypt_data(data, self.password)
            write_file_preserve_time(filepath, enc)
        else:
            dec = decrypt_data(data, self.password)
            write_file_preserve_time(filepath, dec)

def create_label(text, bold=False, size=11):
    lbl = QLabel(text)
    font = QFont('Segoe UI', size)
    font.setBold(bold)
    lbl.setFont(font)
    return lbl

def create_line_edit(password=False):
    le = QLineEdit()
    le.setFont(QFont('Segoe UI', 11))
    if password:
        le.setEchoMode(QLineEdit.Password)
    le.setFixedHeight(30)
    return le

def create_button(text):
    btn = QPushButton(text)
    btn.setFont(QFont('Segoe UI', 11))
    btn.setFixedHeight(36)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    return btn

def setup_ui():
    win = QWidget()
    win.setWindowTitle("🔒 File Encrypt/Decrypt Tool")
    win.setGeometry(400, 200, 680, 340)
    win.setMinimumSize(640, 320)
    win.setStyleSheet("""
        QWidget {
            background-color: #fefefe;
        }
        QPushButton {
            background-color: #1678c2;
            color: white;
            border-radius: 6px;
            padding: 4px 12px;
        }
        QPushButton:hover {
            background-color: #0e57a6;
        }
        QPushButton:pressed {
            background-color: #094574;
        }
        QLineEdit {
            border: 1.5px solid #ccc;
            border-radius: 6px;
            padding-left: 10px;
            background-color: #fff;
        }
        QLabel {
            color: #222;
        }
        QTextEdit {
            border: 1.5px solid #ccc;
            border-radius: 6px;
            background-color: #fff;
            padding: 6px;
            font-family: Consolas, monospace;
            font-size: 11pt;
        }
    """)

    layout = QVBoxLayout()

    title_label = create_label("File Encryption / Decryption Tool", bold=True, size=18)
    title_label.setAlignment(Qt.AlignCenter)
    layout.addWidget(title_label)
    layout.addSpacing(12)

    # 路径选择布局
    hl_path = QHBoxLayout()
    label_path = create_label("File or Directory:", bold=True)
    le_path = QLineEdit()
    le_path.setReadOnly(True)
    le_path.setFixedHeight(30)
    btn_browse = create_button("Browse")
    btn_browse.setMaximumWidth(140)
    hl_path.addWidget(label_path, 1)
    hl_path.addWidget(le_path, 6)
    hl_path.addWidget(btn_browse, 1)
    layout.addLayout(hl_path)
    layout.addSpacing(10)

    # 密码输入
    hl_pwd = QHBoxLayout()
    label_pwd = create_label("Password:", bold=True)
    le_pwd = create_line_edit(password=True)
    hl_pwd.addWidget(label_pwd, 1)
    hl_pwd.addWidget(le_pwd, 6)
    layout.addLayout(hl_pwd)
    layout.addSpacing(8)

    # 确认密码 (只针对加密）
    hl_confirm = QHBoxLayout()
    label_confirm = create_label("Confirm Password (only for Encryption):", bold=True)
    le_confirm = create_line_edit(password=True)
    hl_confirm.addWidget(label_confirm, 1)
    hl_confirm.addWidget(le_confirm, 6)
    layout.addLayout(hl_confirm)
    layout.addSpacing(15)

    # 操作按钮
    hl_btn = QHBoxLayout()
    btn_encrypt = create_button("Encrypt")
    btn_decrypt = create_button("Decrypt")
    hl_btn.addStretch(1)
    hl_btn.addWidget(btn_encrypt, 1)
    hl_btn.addSpacing(20)
    hl_btn.addWidget(btn_decrypt, 1)
    hl_btn.addStretch(1)
    layout.addLayout(hl_btn)
    layout.addSpacing(15)

    # 日志区
    label_log = create_label("Log:")
    te_log = QTextEdit()
    te_log.setReadOnly(True)
    te_log.setFixedHeight(110)
    layout.addWidget(label_log)
    layout.addWidget(te_log)

    win.setLayout(layout)

    return {
        'window': win,
        'le_path': le_path,
        'btn_browse': btn_browse,
        'le_pwd': le_pwd,
        'le_confirm': le_confirm,
        'btn_encrypt': btn_encrypt,
        'btn_decrypt': btn_decrypt,
        'te_log': te_log
    }

def log(te_log, message):
    te_log.append(message)
    te_log.verticalScrollBar().setValue(te_log.verticalScrollBar().maximum())

def on_browse(le_path, te_log):
    path = select_path()
    if path:
        le_path.setText(path)
        log(te_log, f'Path selected:\n{path}')

def validate_inputs(path, pwd, conf_pwd, mode, parent, te_log):
    if not path:
        msg_box(parent, "Input Error", "Please select file or directory first.")
        return False
    if not os.path.exists(path):
        msg_box(parent, "Input Error", "Selected path does not exist.")
        return False
    if not pwd:
        msg_box(parent, "Input Error", "Password cannot be empty.")
        return False
    if mode == 'encrypt' and pwd != conf_pwd:
        msg_box(parent, "Input Error", "Password and confirm password do not match.")
        return False
    log(te_log, f"Inputs validated for {mode}.")
    return True

def start_worker(mode, path, pwd, parent, te_log):
    worker = WorkerThread(mode, path, pwd)
    worker.finished_signal.connect(lambda msg: on_worker_finished(msg, parent, te_log))
    worker.error_signal.connect(lambda err: on_worker_error(err, parent, te_log))
    worker.start()
    log(te_log, f"{mode.title()} started in background thread for:\n{path}")

def on_worker_finished(msg, parent, te_log):
    log(te_log, "✔ " + msg)
    msg_box(parent, "Success", msg)

def on_worker_error(err, parent, te_log):
    log(te_log, "❌ " + err)
    msg_box(parent, "Error", err)

def on_encrypt_click(le_path, le_pwd, le_confirm, parent, te_log):
    path = le_path.text().strip()
    pwd = le_pwd.text()
    conf = le_confirm.text()
    if not validate_inputs(path, pwd, conf, 'encrypt', parent, te_log):
        return
    start_worker('encrypt', path, pwd, parent, te_log)

def on_decrypt_click(le_path, le_pwd, parent, te_log):
    path = le_path.text().strip()
    pwd = le_pwd.text()
    if not validate_inputs(path, pwd, '', 'decrypt', parent, te_log):
        return
    start_worker('decrypt', path, pwd, parent, te_log)

def main():
    app = QApplication(sys.argv)
    ui = setup_ui()

    win = ui['window']
    le_path = ui['le_path']
    btn_browse = ui['btn_browse']
    le_pwd = ui['le_pwd']
    le_confirm = ui['le_confirm']
    btn_encrypt = ui['btn_encrypt']
    btn_decrypt = ui['btn_decrypt']
    te_log = ui['te_log']

    btn_browse.clicked.connect(lambda: on_browse(le_path, te_log))
    btn_encrypt.clicked.connect(lambda: on_encrypt_click(le_path, le_pwd, le_confirm, win, te_log))
    btn_decrypt.clicked.connect(lambda: on_decrypt_click(le_path, le_pwd, win, te_log))

    win.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
