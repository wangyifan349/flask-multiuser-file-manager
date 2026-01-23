"""
simple_cloud_disk.py

A simple multi-user cloud disk (webdisk/netdisk) application based on Flask+sqlite+Bootstrap.  
Supports user registration/login, multi-file upload, hierarchical directories, drag-and-drop move, download, right-click operations (delete, rename/move), and per-user file isolation.  
All frontend and backend code are contained in a single file for easy one-click deployment.
"""

import os
import shutil
import sqlite3
from flask import Flask, request, send_from_directory, jsonify, abort, session, g, redirect, url_for, render_template_string

app = Flask(__name__)
app.config['UPLOAD_ROOT'] = 'user_files'                         # Directory to store all users' files
app.config['DATABASE'] = 'user_accounts.db'                      # sqlite3 database file
app.config['SECRET_KEY'] = 'change_this_key'                     # Flask session secret

if not os.path.exists(app.config['UPLOAD_ROOT']):                # Ensure root directory exists
    os.makedirs(app.config['UPLOAD_ROOT'])

# ======================== DATABASE =========================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])           # Connect to sqlite3
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()                                               # Close DB after request

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );''')                                                       # Create users table
    db.commit()

with app.app_context():
    init_db()                                                    # Auto create DB/tables at startup

from werkzeug.security import generate_password_hash, check_password_hash

# =============== PATH SECURITY AND USER SPACE ==============
def get_user_root(username):
    user_root = os.path.join(app.config['UPLOAD_ROOT'], username)  # Sub-directory for user
    abs_user_root = os.path.abspath(user_root)
    if not abs_user_root.startswith(os.path.abspath(app.config['UPLOAD_ROOT'])):
        abort(400, description="Invalid username.")
    return user_root

def safe_user_path(username, relative_path):
    user_root = get_user_root(username)
    abs_user_root = os.path.abspath(user_root)
    target_abs = os.path.abspath(os.path.join(user_root, relative_path))
    if not target_abs.startswith(abs_user_root):
        abort(400, description="Invalid path.")
    return target_abs

def ensure_user_root(username):
    user_root = get_user_root(username)
    if not os.path.exists(user_root):
        os.makedirs(user_root)                                   # Ensure user's root dir exists
    return user_root

# ===================== AUTH DECORATOR ======================
def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Not logged in'}), 401
        return func(*args, **kwargs)
    return wrapper

# ===================== FRONTEND PAGES ======================
login_page_html = r'''
<!doctype html>
<html lang="en">
<!-- Login/Register page, uses Bootstrap for styling -->
<head>
    <meta charset="utf-8">
    <title>Sign in / Register</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-12 col-sm-10 col-md-6 col-lg-4">
            <div class="card shadow">
                <div class="card-body">
                    <h3 class="mb-3 text-center">Sign in</h3>
                    <form id="login_form">
                        <div class="mb-2">
                            <input type="text" name="username" id="login_username" class="form-control" placeholder="Username" required>
                        </div>
                        <div class="mb-2">
                            <input type="password" name="password" id="login_password" class="form-control" placeholder="Password" required>
                        </div>
                        <button class="btn btn-primary w-100" type="submit">Sign in</button>
                    </form>
                    <hr>
                    <h3 class="mb-3 text-center">Register</h3>
                    <form id="register_form">
                        <div class="mb-2">
                            <input type="text" name="username" id="register_username" class="form-control" placeholder="Username" required>
                        </div>
                        <div class="mb-2">
                            <input type="password" name="password" id="register_password" class="form-control" placeholder="Password" required>
                        </div>
                        <button class="btn btn-success w-100" type="submit">Register</button>
                    </form>
                    <div id="notice_message" class="mt-3 text-center"></div>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
document.getElementById('login_form').onsubmit = async function(e) {
    e.preventDefault();
    let form = new FormData(this);
    let resp = await fetch('/login', {method:'POST', body:form});
    let data = await resp.json();
    if(resp.ok){
        location.href = '/disk';                  // Go to disk page on success
    }else{
        document.getElementById('notice_message').textContent = data.error || data.message || 'Sign in failed';
    }
}
document.getElementById('register_form').onsubmit = async function(e) {
    e.preventDefault();
    let form = new FormData(this);
    let resp = await fetch('/register', {method:'POST', body:form});
    let data = await resp.json();
    if(resp.ok){
        document.getElementById('notice_message').textContent = "Register succeeded. Please sign in.";
    }else{
        document.getElementById('notice_message').textContent = data.error || data.message || 'Register failed';
    }
}
</script>
</body>
</html>
'''

disk_page_html = r'''
<!doctype html>
<html lang="en">
<!-- File manager page, Bootstrap and FontAwesome, with drag-and-drop, context menu etc. -->
<head>
    <meta charset="utf-8">
    <title>Personal Cloud Disk</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <style>
        #file_list_area {min-height:60vh;}
        .file_item {cursor:pointer;}
        .drag_over {background:#f0f0f0;}
        .context_menu {display:none;position:absolute;z-index:9999;background:#fff;border:1px solid #999;box-shadow:2px 2px 5px #999;}
        .context_menu li {list-style:none; padding:4px 20px; cursor:pointer;}
        .context_menu li:hover {background:#f4f4f4;}
    </style>
</head>
<body>
<div class="container-fluid py-3">
    <div class="d-flex">
        <h3>Cloud Disk</h3>
        <button class="btn btn-outline-secondary ms-auto" id="logout_btn">Logout</button>
    </div>
    <hr>
    <div class="mb-2">
        <button class="btn btn-success btn-sm" id="create_dir_btn"><i class="fa fa-folder-plus"></i> New Folder</button>
        <input type="file" id="file_upload_input" multiple style="display:none;">
        <button class="btn btn-primary btn-sm" id="upload_btn"><i class="fa fa-upload"></i> Upload</button>
        <button class="btn btn-outline-info btn-sm" id="refresh_btn"><i class="fa fa-refresh"></i> Refresh</button>
        <span id="current_rel_path"></span>
    </div>
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb" id="breadcrumb_bar"></ol>
    </nav>
    <ul class="list-group" id="file_list_area"></ul>
</div>

<ul class="context_menu" id="context_menu_area">
    <li data-action="download"><i class="fa fa-download me-2"></i>Download</li>
    <li data-action="rename"><i class="fa fa-pen me-2"></i>Rename / Move</li>
    <li data-action="delete"><i class="fa fa-trash me-2"></i>Delete</li>
</ul>

<script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.2/Sortable.min.js"></script>
<script>
let current_path = "";    // Current relative folder

async function load_file_list(rel_path){
    let resp = await fetch('/api/list?path='+encodeURIComponent(rel_path||''));
    if(resp.status==401){location.href="/";return}
    let data = await resp.json();
    if(!resp.ok){alert(data.error);return}
    render_file_list(data.items);
    current_path = rel_path||"";
    document.getElementById('current_rel_path').textContent = (current_path==""?"/":current_path);
    render_breadcrumb_bar();
}
function render_file_list(items){
    let list = document.getElementById('file_list_area');
    list.innerHTML="";
    if(current_path!=""){
        let li = document.createElement("li");
        li.className="list-group-item file_item";
        li.innerHTML = '<i class="fa fa-level-up-alt"></i> ..';
        li.onclick = ()=>{go_parent_dir();}       // Go up parent directory
        list.appendChild(li);
    }
    for(let item of items){
        let li = document.createElement("li");
        li.className="list-group-item d-flex align-items-center file_item";
        li.setAttribute("data-name", item.name);
        li.setAttribute("data-type", item.type);
        li.setAttribute('draggable','true');
        li.innerHTML = (item.type=='dir'?
            `<i class="fa fa-folder text-warning me-2"></i>`:
            `<i class="fa fa-file text-secondary me-2"></i>`);
        li.innerHTML += `<span style="flex:1;">${item.name}</span>`;
        list.appendChild(li);
        if(item.type=='dir'){
            li.ondblclick = ()=>{open_dir(item.name);}
        }
    }
}

function render_breadcrumb_bar(){
    let bc = document.getElementById("breadcrumb_bar");
    let segs = (current_path?current_path.split('/'):[]);
    bc.innerHTML = "";
    let path = "";
    let root = document.createElement('li');
    root.className = "breadcrumb-item";
    root.innerHTML = '<a href="#">Home</a>';
    root.onclick = ()=>{load_file_list('');};
    bc.appendChild(root)
    for (let i=0; i<segs.length;i++){
        path += (i==0?"":"/") + segs[i];
        let li = document.createElement('li');
        li.className="breadcrumb-item";
        if(i==segs.length-1)
            li.classList.add("active");
        li.innerHTML = `<a href="#">${segs[i]}</a>`;
        li.onclick = ()=>{load_file_list(segs.slice(0,i+1).join('/'));};
        bc.appendChild(li);
    }
}
function go_parent_dir(){
    let segs=current_path.split('/');
    segs.pop();load_file_list(segs.join('/'));
}
function open_dir(name){
    let path = (current_path?current_path+'/':'')+name;
    load_file_list(path);
}

// Drag and drop move
let dragging_item = null;
document.getElementById("file_list_area").addEventListener("dragstart", function(e){
    let li = e.target.closest(".file_item");
    if(!li || (li.getAttribute("data-type")!=="file" && li.getAttribute("data-type")!=="dir")) return;
    dragging_item = li.getAttribute("data-name");
    e.dataTransfer.effectAllowed = "move";
});
document.getElementById("file_list_area").addEventListener("dragover", function(e){
    e.preventDefault();
    let li = e.target.closest(".file_item");
    if(li && li.getAttribute("data-type")=="dir"){
        li.classList.add("drag_over");            // Highlight folder
    }
});
document.getElementById("file_list_area").addEventListener("dragleave", function(e){
    let li = e.target.closest(".file_item");
    if(li && li.getAttribute("data-type")=="dir"){
        li.classList.remove("drag_over");
    }
});
document.getElementById("file_list_area").addEventListener("drop", function(e){
    e.preventDefault();
    let li = e.target.closest(".file_item");
    if(!li || li.getAttribute("data-type")!=="dir"||!dragging_item) return;
    li.classList.remove("drag_over");
    let src = (current_path?current_path+'/':'')+dragging_item;
    let dst = (current_path?current_path+'/':'') + li.getAttribute("data-name") + "/" + dragging_item;
    fetch('/api/move', {
        method:'POST',
        body: new URLSearchParams({src: src, dst: dst})
    }).then(r=>r.json()).then(data=>{
        if(data.error){alert(data.error);}else{load_file_list(current_path);}
    });
    dragging_item=null;
});

// Context menu (right-click) and actions
let context_menu_area = document.getElementById("context_menu_area");
document.getElementById("file_list_area").addEventListener("contextmenu", function(e){
    let li = e.target.closest(".file_item");
    if(li && li.getAttribute("data-name") && li.innerText!=='..'){
        e.preventDefault();
        context_menu_area.style.left = e.pageX+"px";
        context_menu_area.style.top = e.pageY+"px";
        context_menu_area.style.display = 'block';
        context_menu_area.setAttribute('data-name', li.getAttribute("data-name"));
        context_menu_area.setAttribute('data-type', li.getAttribute("data-type"));
    }
});
document.body.addEventListener("click", ()=>context_menu_area.style.display='none');
context_menu_area.addEventListener("click", function(e){
    let act = e.target.closest('li');
    if(!act) return;
    let name = context_menu_area.getAttribute('data-name');
    let type = context_menu_area.getAttribute('data-type');
    let path = (current_path?current_path+'/':'')+name;
    if(act.dataset.action=='download'){
        if(type!='file'){alert("Only files can be downloaded."); return;}
        window.open('/api/download?path='+encodeURIComponent(path));       // Download file
    } else if(act.dataset.action=='delete'){
        if(confirm("Permanently delete?")){
            fetch('/api/delete', {
                method:'POST',
                body: new URLSearchParams({path: path})
            }).then(r=>r.json()).then(data=>{
                if(data.error){alert(data.error);}else{load_file_list(current_path);}
            });
        }
    } else if(act.dataset.action=='rename'){
        let newname = prompt("Rename / Move to (new path):", name);
        if(!newname||newname==name) return;
        let dst = (current_path?current_path+'/':'')+newname;
        fetch('/api/move',{
            method:'POST',body:new URLSearchParams({src: path, dst: dst})
        }).then(r=>r.json()).then(data=>{
            if(data.error){alert(data.error);}else{load_file_list(current_path);}
        });
    }
});

// Upload
document.getElementById('upload_btn').onclick = ()=>document.getElementById('file_upload_input').click();
document.getElementById('file_upload_input').onchange = function(){
    let files = this.files;
    let form = new FormData();
    for(let f of files) form.append('files', f);
    form.append('destination_folder', current_path);
    fetch('/api/upload', {method:'POST', body:form}).then(r=>r.json()).then(data=>{
        if(data.error){alert(data.error);}else{load_file_list(current_path);}
    });
    this.value="";
}

// New folder
document.getElementById('create_dir_btn').onclick = function(){
    let name = prompt("Folder name");
    if(!name)return;
    let dir = current_path ? current_path+"/"+name:name;
    fetch('/api/mkdir', {method:'POST', body: new URLSearchParams({dir_path: dir})})
        .then(r=>r.json()).then(data=>{
        if(data.error){alert(data.error);}else{load_file_list(current_path);}
    });
}
// Refresh
document.getElementById('refresh_btn').onclick=()=>load_file_list(current_path);
// Logout
document.getElementById('logout_btn').onclick = function(){
    fetch('/logout').then(()=>location.href="/");   // Logout and redirect to login
}

// Initial
load_file_list("");
</script>
</body>
</html>
'''

# ===================== ROUTES FOR FRONTEND =========================
@app.route('/')
def route_login_page():
    if 'username' in session:                   # Auto redirect if already signed in
        return redirect(url_for('route_disk_page'))
    return render_template_string(login_page_html)

@app.route('/disk')
def route_disk_page():
    if 'username' not in session:
        return redirect(url_for('route_login_page'))
    return render_template_string(disk_page_html)

# ===================== USER AUTH API ===============================
@app.route('/register', methods=['POST'])
def api_register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
    if user:
        return jsonify({'error': 'User already exists'}), 409
    db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
               (username, generate_password_hash(password)))  # Encrypted password
    db.commit()
    ensure_user_root(username)
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/login', methods=['POST'])
def api_login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if user and check_password_hash(user['password'], password):
        session['username'] = username
        ensure_user_root(username)
        return jsonify({'message': 'Sign in successful'})
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/logout')
def api_logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out'})

# ===================== FILE MANAGER API ==============================
@app.route('/api/list', methods=['GET'])
@login_required
def api_list_files():
    rel_path = request.args.get('path', '')
    username = session['username']
    abs_dir_path = safe_user_path(username, rel_path)
    if not os.path.isdir(abs_dir_path):
        return jsonify({'error': 'Not a directory'}), 400
    items = []
    for name in sorted(os.listdir(abs_dir_path)):
        abs_item = os.path.join(abs_dir_path, name)
        item_type = 'dir' if os.path.isdir(abs_item) else 'file'
        items.append({'name': name, 'type': item_type})       # Compose directory/file info
    return jsonify({'items': items})

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    username = session['username']
    files = request.files.getlist('files')
    destination_folder = request.form.get('destination_folder', '')
    save_folder = safe_user_path(username, destination_folder)
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)
    saved_files = []
    for uploaded_file in files:
        if uploaded_file.filename == '':
            continue
        safe_filename = os.path.basename(uploaded_file.filename)
        file_path = os.path.join(save_folder, safe_filename)
        uploaded_file.save(file_path)
        saved_files.append(os.path.relpath(file_path, get_user_root(username)))
    return jsonify({'uploaded': saved_files}), 201

@app.route('/api/mkdir', methods=['POST'])
@login_required
def api_make_dir():
    dir_path = request.form.get('dir_path', '')
    if not dir_path:
        return jsonify({'error': 'No folder name provided'}), 400
    username = session['username']
    abs_folder_path = safe_user_path(username, dir_path)
    if not os.path.exists(abs_folder_path):
        os.makedirs(abs_folder_path)
    return jsonify({'created': os.path.relpath(abs_folder_path, get_user_root(username))}), 201

@app.route('/api/move', methods=['POST'])
@login_required
def api_move():
    src = request.form.get('src', '')
    dst = request.form.get('dst', '')
    if not src or not dst:
        return jsonify({'error': 'Missing src or dst'}), 400
    username = session['username']
    src_abs = safe_user_path(username, src)
    dst_abs = safe_user_path(username, dst)
    if not os.path.exists(src_abs):
        return jsonify({'error': 'Source does not exist'}), 404
    if os.path.exists(dst_abs):
        return jsonify({'error': 'Destination already exists'}), 400
    os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
    shutil.move(src_abs, dst_abs)                        # Move file or folder
    return jsonify({'moved_from': src, 'moved_to': dst})

@app.route('/api/download', methods=['GET'])
@login_required
def api_download():
    rel_path = request.args.get('path', '')
    if not rel_path:
        return jsonify({'error': 'No path provided'}), 400
    username = session['username']
    abs_file_path = safe_user_path(username, rel_path)
    if not os.path.isfile(abs_file_path):
        return jsonify({'error': 'File does not exist'}), 404
    parent_dir, filename = os.path.split(abs_file_path)
    return send_from_directory(parent_dir, filename, as_attachment=True)  # Download

@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    path = request.form.get('path', '')
    if not path:
        return jsonify({'error': 'No path provided'}), 400
    username = session['username']
    abs_path = safe_user_path(username, path)
    if not os.path.exists(abs_path):
        return jsonify({'error': 'Path does not exist'}), 404
    try:
        if os.path.isfile(abs_path) or os.path.islink(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            shutil.rmtree(abs_path)         # Recursively remove directory
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'deleted': path})

if __name__ == '__main__':
    app.run(debug=True)                    # Launch Flask dev server
