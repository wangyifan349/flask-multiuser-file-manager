# Flask Multi-User File Management System 🗂️✨

Welcome to the [wangyifan349/Flask File Management System](https://github.com/wangyifan349) repository!

---

## 🚀 Project Overview

This lightweight, multi-user file management system is built with **Flask**, designed to help individuals or small teams easily manage files and directories with an intuitive web interface.

### Key Features:

- 🔐 **Secure User Registration & Login**  
  User credentials are safely stored using SQLite and password hashes to protect your data.

- 📁 **Hierarchical Directory Browsing**  
  Navigate through nested folders seamlessly to organize and access your files.

- 📥 **File Upload & Folder Creation**  
  Upload common file types directly and create new folders to keep your files structured.

- 📤 **Easy File Download**  
  Download files effortlessly with a click.

- 📝 **Rename & Delete Files/Folders (AJAX-Powered)**  
  Right-click context menus and buttons allow in-place renaming and deletion without page reloads.

- 🔄 **Drag & Drop File/Folder Movement**  
  Rearrange your file system with smooth drag-and-drop support—just drag files or folders into any target folder.

- 🎨 **Modern UI with Bootstrap 4 & FontAwesome**  
  Responsive, clean, and user-friendly interface that works across devices.

- 🛡️ **Robust Path Security**  
  Prevents directory traversal attacks; users can only access and manipulate their own files.

- ⚙️ **Single-File Deployment**  
  All-in-one `app.py` script ready to run immediately—perfect for quick setup and further customization.

---

## 🔧 Requirements

- Python 3.7 or higher
- Flask
- Werkzeug (for password hashing)
- SQLite3 (built-in with Python)

### Install dependencies:

```bash
pip install flask werkzeug
```

---

## 🚩 Quick Start Guide

1. Clone this repository or download the `app.py` file.

2. Run the application:

```bash
python app.py
```

3. Open your browser and navigate to:

```
http://127.0.0.1:5000
```

4. Register a new user, then log in to start managing your files!

---

## 🎯 Use Cases

- Personal file organization and backup 📂  
- Small team file sharing and collaboration 👥  
- Educational project or reference for building file management apps 🎓  

---

## 💡 Potential Enhancements

- Integrate ORM like SQLAlchemy for advanced DB management  
- Add granular file permissions and multi-user sharing  
- Provide file preview functionality directly in browser  
- Implement file version control and history tracking  
- Adopt more secure authentication methods (OAuth2, JWT, etc.)  

---

## 🧑‍💻 Author & Contributions

Maintained by [@wangyifan349](https://github.com/wangyifan349).  
Feel free to ⭐ Star and 🍴 Fork the project!  
Issues and Pull Requests are warmly welcome.

---

## 💖 Thank you for using this project! Happy coding! 🎉

---

[![GitHub stars](https://img.shields.io/github/stars/wangyifan349.svg?style=social&label=Star)](https://github.com/wangyifan349)  
[![GitHub forks](https://img.shields.io/github/forks/wangyifan349.svg?style=social&label=Fork)](https://github.com/wangyifan349)

---

✨✨✨
