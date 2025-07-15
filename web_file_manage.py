from flask import Flask, request, send_from_directory, jsonify, render_template_string, redirect, url_for  # Import Flask modules for web handling
import os  # For filesystem operations
import werkzeug  # For secure filename utility

app = Flask(__name__)  # Create Flask app instance

# Define upload folder path relative to this script's directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')  
if not os.path.exists(UPLOAD_FOLDER):  # Check if the folder exists
    os.makedirs(UPLOAD_FOLDER)  # Create the uploads folder if missing

# App configurations
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Set upload folder in config
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Limit upload size to 100MB

# ----------------------------------------------
def safe_join(base, *paths):  # Securely join paths to prevent directory traversal
    final_path = os.path.normpath(os.path.join(base, *paths))  # Normalize combined path
    if not final_path.startswith(os.path.abspath(base)):  # Check if final path is within base directory
        raise ValueError('非法路径')  # Raise error on illegal path (prevent path traversal)
    return final_path  # Return normalized safe path

# ----------------------------------------------
@app.route('/')  # Route for index page showing file browser
def index():
    rel_path = request.args.get('path', '')  # Get relative path query string parameter, default root
    try:
        abs_path = safe_join(app.config['UPLOAD_FOLDER'], rel_path)  # Resolve real full path safely
    except Exception:
        return "非法路径", 400  # Return error on illegal path
    if not os.path.exists(abs_path):  # Check path existence
        return "目录不存在", 404  # Folder not found error
    if not os.path.isdir(abs_path):  # If not directory redirect to root
        return redirect(url_for('index'))

    entries = os.listdir(abs_path)  # List contents of directory
    dirs = []  # Initialize directory list
    files = []  # Initialize files list
    for e in entries:
        full_e = os.path.join(abs_path, e)  # Full path of entry
        if os.path.isdir(full_e):  # Check if directory
            dirs.append(e)  # Append to dirs
        elif os.path.isfile(full_e):  # Check if file
            files.append(e)  # Append to files

    # HTML template string for rendering directory listing and UI
    html = '''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>简单网盘 - 目录浏览</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
#fileList { margin-top: 20px; }
.fileItem, .dirItem { padding: 5px; border: 1px solid #ddd; margin-bottom: 4px; cursor: pointer; user-select: none; }
.dirItem { font-weight: bold; background-color: #f0f0f0; }
.fileItem.dragging, .dirItem.dragging { opacity: 0.4; }  /* Transparency for dragging */
.context-menu { display: none; position: absolute; background: #fff; border: 1px solid #ccc; box-shadow: 2px 2px 6px rgba(0,0,0,0.2);}
.context-menu ul { list-style: none; padding: 5px 0; margin: 0;}
.context-menu ul li { padding: 5px 20px; cursor: pointer; }
.context-menu ul li:hover { background-color: #eee; }
</style>
</head>
<body>

<h2>简单网盘 - 目录浏览</h2>

<div>
当前目录: /{{ rel_path }}/
</div>

<div>
<a href="?path={{ parent_path }}">[上级目录]</a>  <!-- Link to parent directory -->
</div>

<input type="file" id="uploadFile" />
<button id="uploadBtn">上传</button>

<div id="fileList" ondragover="event.preventDefault();" ondrop="handleDrop(event);">  <!-- File list container accepts drag-and-drop -->
  {% for d in dirs %}
  <div class="dirItem" draggable="true" data-name="{{d}}" data-type="dir">[目录] {{d}}</div>  <!-- Directory item draggable -->
  {% endfor %}
  {% for f in files %}
  <div class="fileItem" draggable="true" data-name="{{f}}" data-type="file">{{f}}</div>  <!-- File item draggable -->
  {% endfor %}
</div>

<div class="context-menu" id="contextMenu">  <!-- Context menu with options -->
  <ul>
    <li id="download">下载</li>
    <li id="rename">重命名</li>
    <li id="delete">删除</li>
  </ul>
</div>

<script>
let relPath = '{{ rel_path }}';  // Current folder path
let draggedEl = null;  // Element currently dragged
let currentRightClickedName = null;  // Name of right-clicked file or directory
let currentRightClickedType = null;  // Type: file or dir
let contextMenu = document.getElementById('contextMenu');  // Context menu element

document.getElementById('uploadBtn').addEventListener('click', function() {
  let uploadInput = document.getElementById('uploadFile');
  if (uploadInput.files.length === 0) {
    alert('请选择文件');  // If no file selected, alert
    return;
  }
  let file = uploadInput.files[0];
  let formData = new FormData();
  formData.append('file', file);  // Append file to form data
  formData.append('path', relPath);  // Append current path
  fetch('/upload', {method:'POST', body: formData})  // POST upload request
  .then(response => response.json())
  .then(data => {
    alert(data.message);  // Show message returned from server
    if (data.success) {
      location.reload();  // Reload page on success
    }
  });
});

document.querySelectorAll('.dirItem, .fileItem').forEach(function(el) {
  el.addEventListener('dragstart', function(e) {
    draggedEl = e.target;  // Remember dragged element
    e.dataTransfer.setData('text/plain', JSON.stringify({   // Set drag data as JSON string
      name: draggedEl.getAttribute('data-name'),
      type: draggedEl.getAttribute('data-type')
    }));
    draggedEl.classList.add('dragging');  // Add dragging opacity style
  });
  el.addEventListener('dragend', function(e) {
    if (draggedEl) {
      draggedEl.classList.remove('dragging');  // Remove dragging style on end
      draggedEl = null;  // Clear dragged reference
    }
  });
});

document.querySelectorAll('.dirItem').forEach(function(el){
  // clicking directory navigates into it
  el.addEventListener('click', function() {
    let name = el.getAttribute('data-name');
    let nextPath = relPath ? relPath + '/' + name : name;
    location.href = '?path=' + encodeURIComponent(nextPath);
  });

  // allow drag over directory (for drop)
  el.addEventListener('dragover', function(e) {
    e.preventDefault();  // Allow drop by preventing default
  });
  el.addEventListener('drop', function(e) {
    e.preventDefault();
    if (!draggedEl) return;
    let sourceData = JSON.parse(e.dataTransfer.getData('text/plain'));
    let sourceName = sourceData.name;
    let sourceType = sourceData.type;
    let targetName = el.getAttribute('data-name');
    // Prevent moving directory onto itself
    if (sourceName === targetName && sourceType === 'dir' && draggedEl === el) {
      return;
    }
    let sourcePath = relPath ? relPath + '/' + sourceName : sourceName;
    let targetPath = relPath ? relPath + '/' + targetName : targetName;
    // Call server move API with JSON body
    fetch('/move', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        source_path: sourcePath,
        target_dir: targetPath,
      }),
    }).then(res => res.json()).then(data => {
      alert(data.message);  // Show response message
      if (data.success) {
        location.reload();  // Reload page on success
      }
    });
  });
});

let fileListEl = document.getElementById('fileList');

fileListEl.addEventListener('contextmenu', function(e) {
  e.preventDefault();  // Prevent default right-click menu
  let target = e.target;
  if (target.classList.contains('fileItem') || target.classList.contains('dirItem')) {
    currentRightClickedName = target.getAttribute('data-name');  // Get name of clicked item
    currentRightClickedType = target.getAttribute('data-type');  // Get type
    showContextMenu(e.pageX, e.pageY);  // Show custom context menu at cursor
  } else {
    contextMenu.style.display = 'none';  // Hide menu if click not on item
  }
});

function showContextMenu(x,y) {
  contextMenu.style.left = x + 'px';  // Set menu horizontal position
  contextMenu.style.top = y + 'px';   // Set menu vertical position
  contextMenu.style.display = 'block';  // Make menu visible
}

window.addEventListener('click', function() {
  contextMenu.style.display = 'none';  // Hide menu on any click outside
});

// Download file (only allowed on files)
document.getElementById('download').addEventListener('click', function() {
  if (!currentRightClickedName) return;
  if (currentRightClickedType !== 'file') {
    alert('只能下载文件');  // Only files are downloadable
    contextMenu.style.display = 'none';  // Hide context menu
    return;
  }
  let fullPath = relPath ? relPath + '/' + currentRightClickedName : currentRightClickedName;
  window.location.href = '/download/' + encodeURIComponent(fullPath);  // Trigger download link
  contextMenu.style.display = 'none';  // Hide menu
});

// Delete a file or directory after confirmation
document.getElementById('delete').addEventListener('click', function() {
  if (!currentRightClickedName) return;
  if (!confirm('确认删除 "' + currentRightClickedName + '" 吗？')) return;  // Confirmation dialog
  let fullPath = relPath ? relPath + '/' + currentRightClickedName : currentRightClickedName;
  fetch('/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({filepath: fullPath, type: currentRightClickedType})
  })
  .then(response => response.json())
  .then(data => {
    alert(data.message);  // Show delete result
    if (data.success) location.reload();  // Reload on success
  });
  contextMenu.style.display = 'none';  // Hide menu
});

// Rename a file or directory with prompt input
document.getElementById('rename').addEventListener('click', function() {
  if (!currentRightClickedName) return;
  let newName = prompt('输入新名称', currentRightClickedName);  // Prompt for new name
  if (newName === null || newName.trim() === '') return;  // Cancel or empty input
  let fullPath = relPath ? relPath + '/' + currentRightClickedName : currentRightClickedName;
  fetch('/rename', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({old_path: fullPath, new_name: newName, type: currentRightClickedType})
  })
  .then(response => response.json())
  .then(data => {
    alert(data.message);  // Show rename result
    if (data.success) location.reload();  // Reload on success
  });
  contextMenu.style.display = 'none';  // Hide menu
});

// No operation drop handler just to prevent default file drop outside targets
function handleDrop(event) {
  event.preventDefault();  // Prevent browser's default drop behavior
}

</script>

</body>
</html>
'''

    parent_path = ''  # Calculate parent directory path
    if rel_path:
        parts = rel_path.split('/')
        parent_path = '/'.join(parts[:-1])  # Parent is all but last part
    else:
        parent_path = ''  # Root has no parent

    # Render HTML template with directory and file data
    return render_template_string(html, rel_path=rel_path, parent_path=parent_path, dirs=dirs, files=files)

# ----------------------------------------------
@app.route('/upload', methods=['POST'])  # Upload file handler
def upload():
    if 'file' not in request.files:  # Check file form data present
        return jsonify({'message': '没有上传文件', 'success': False}), 400
    file = request.files['file']  # Get uploaded file
    if file.filename == '':  # Check filename not empty
        return jsonify({'message': '空文件名', 'success': False}), 400
    path = request.form.get('path', '')  # Get target subfolder relative path
    try:
        abs_dir = safe_join(app.config['UPLOAD_FOLDER'], path)  # Safe absolute directory path
    except Exception:
        return jsonify({'message': '非法路径', 'success': False}), 400
    if not os.path.exists(abs_dir):
        os.makedirs(abs_dir)  # Create directory if missing

    filename = werkzeug.utils.secure_filename(file.filename)  # Sanitize filename
    save_path = os.path.join(abs_dir, filename)  # Full save path
    file.save(save_path)  # Save file to disk
    return jsonify({'message': '上传成功', 'success': True})  # Success response

# ----------------------------------------------
@app.route('/download/<path:filepath>', methods=['GET'])  # Download a file
def download_file(filepath):
    try:
        abs_fp = safe_join(app.config['UPLOAD_FOLDER'], filepath)  # Resolve real file path
    except Exception:
        return "非法路径", 400
    if not os.path.exists(abs_fp):
        return "文件不存在", 404
    if not os.path.isfile(abs_fp):
        return "不是文件", 400
    rel_dir = os.path.dirname(filepath)  # Directory for send_from_directory
    filename = os.path.basename(filepath)  # Filename to send
    # Send file as attachment for download
    return send_from_directory(safe_join(app.config['UPLOAD_FOLDER'], rel_dir), filename, as_attachment=True)

# ----------------------------------------------
@app.route('/delete', methods=['POST'])  # Delete file or empty directory
def delete_file():
    data = request.get_json(force=True)
    filepath = data.get('filepath')
    ftype = data.get('type')  # 'file' or 'dir'
    if not filepath or not ftype:
        return jsonify({'message': '参数错误', 'success': False}), 400
    try:
        abs_fp = safe_join(app.config['UPLOAD_FOLDER'], filepath)  # Resolve path safely
    except Exception:
        return jsonify({'message': '非法路径', 'success': False}), 400
    if not os.path.exists(abs_fp):
        return jsonify({'message': '文件/目录不存在', 'success': False}), 404
    try:
        if ftype == 'file':
            os.remove(abs_fp)  # Remove file
        elif ftype == 'dir':
            os.rmdir(abs_fp)  # Remove empty directory only
        else:
            return jsonify({'message': '类型错误', 'success': False}), 400
    except Exception as e:
        return jsonify({'message': '删除失败: ' + str(e), 'success': False}), 500
    return jsonify({'message': '删除成功', 'success': True})

# ----------------------------------------------
@app.route('/rename', methods=['POST'])  # Rename file or directory
def rename_file():
    data = request.get_json(force=True)
    old_path = data.get('old_path')
    new_name = data.get('new_name')
    ftype = data.get('type')
    if not old_path or not new_name or not ftype:
        return jsonify({'message': '参数错误', 'success': False}), 400
    try:
        abs_old = safe_join(app.config['UPLOAD_FOLDER'], old_path)  # Old full path safe check
    except Exception:
        return jsonify({'message': '非法路径', 'success': False}), 400
    if not os.path.exists(abs_old):
        return jsonify({'message': '原文件/目录不存在', 'success': False}), 404

    parent_dir = os.path.dirname(abs_old)  # Get parent directory for new path
    new_name_secure = werkzeug.utils.secure_filename(new_name)  # Sanitize new filename
    abs_new = os.path.join(parent_dir, new_name_secure)  # New full path
    if os.path.exists(abs_new):
        return jsonify({'message': '目标文件/目录已存在', 'success': False}), 400
    try:
        os.rename(abs_old, abs_new)  # Rename filesystem entry
    except Exception as e:
        return jsonify({'message': '重命名失败: ' + str(e), 'success': False}), 500
    return jsonify({'message': '重命名成功', 'success': True})

# ----------------------------------------------
@app.route('/move', methods=['POST'])  # Move file or directory to another directory
def move_file_or_dir():
    """
    JSON format:
    {
      "source_path": "a/b/file_or_dir",
      "target_dir": "a/c"
    }
    Moves source_path entry into target_dir directory.
    """
    data = request.get_json(force=True)
    source_path = data.get('source_path')
    target_dir = data.get('target_dir')

    if not source_path or not target_dir:
        return jsonify({'message': '参数错误', 'success': False}), 400
    try:
        abs_source = safe_join(app.config['UPLOAD_FOLDER'], source_path)  # Absolute path of source
        abs_target_dir = safe_join(app.config['UPLOAD_FOLDER'], target_dir)  # Absolute path of target dir
    except Exception:
        return jsonify({'message': '非法路径', 'success': False}), 400

    if not os.path.exists(abs_source):
        return jsonify({'message': '源文件或目录不存在', 'success': False}), 404
    if not os.path.isdir(abs_target_dir):
        return jsonify({'message': '目标目录不存在', 'success': False}), 404

    source_name = os.path.basename(abs_source)  # Name of the moving file/dir
    abs_target = os.path.join(abs_target_dir, source_name)  # Destination full path
    if os.path.exists(abs_target):
        return jsonify({'message': '目标目录已有同名文件或目录', 'success': False}), 400

    # Prevent moving a directory inside itself or its subdirectory
    if os.path.isdir(abs_source):
        abs_source_real = os.path.realpath(abs_source)  # Resolve symlinks
        abs_target_dir_real = os.path.realpath(abs_target_dir)
        if abs_target_dir_real.startswith(abs_source_real):
            return jsonify({'message': '不能移动目录到其自身或子目录', 'success': False}), 400

    try:
        os.rename(abs_source, abs_target)  # Perform move operation
    except Exception as e:
        return jsonify({'message': '移动失败: ' + str(e), 'success': False}), 500

    return jsonify({'message': '移动成功', 'success': True})

# ----------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)  # Start Flask dev server with debug mode enabled
