"""
Flask 文件管理系统
- 使用 SQLite3 存储用户账号密码（安全哈希）
- 支持用户登录注册
- 支持多级目录的文件浏览、上传、下载
- 支持新建文件夹
- 支持AJAX重命名、删除文件夹和文件
- 支持拖拽移动文件夹和文件（AJAX异步操作）
- 使用 Bootstrap4 + FontAwesome 美化界面
- 单文件 app.py，内嵌模板和javascript
"""

import os
import sqlite3
from flask import (
    Flask, request, session, redirect,
    url_for, flash, jsonify, send_file,
    get_flashed_messages
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from jinja2 import Template

app = Flask(__name__)
app.secret_key = 'your_secret_key_please_change!'

# 文件根目录，用户目录即 uploads/用户名/
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 允许上传的文件扩展名
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# SQLite数据库文件
DATABASE = 'users.db'

# ----------- 数据库操作 -----------

def get_db():
    """获得数据库连接，连接关闭需自行调用conn.close()"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """初始化数据库，创建用户表"""
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

def query_user(username: str):
    """查询用户信息，返回Row字典，失败返回None"""
    conn = get_db()
    user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def add_user(username: str, password_hash: str) -> bool:
    """添加用户成功返回True，失败(用户名重复)返回False"""
    try:
        conn = get_db()
        conn.execute('INSERT INTO user (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

init_db()  # 确保数据库和表存在

# ----------- 工具函数 -----------

def allowed_file(filename: str) -> bool:
    """判断文件后缀是否合法"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(func):
    """登录限制装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def safe_join(base: str, *paths: str):
    """
    安全拼接路径，防止目录穿越攻击。
    base: 用户根目录；paths: 子路径
    返回拼接后的绝对路径，非法路径抛ValueError异常。
    """
    base = os.path.abspath(base)
    path = os.path.abspath(os.path.join(base, *paths))
    if not path.startswith(base):
        raise ValueError('非法路径访问')
    return path

# ----------- 内嵌模板渲染函数 -----------

def render_template_string(body_html: str, **context):
    """内嵌模板+Bootstrap4和js，实现基础界面和ajax右键菜单功能"""
    base_template = '''
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>{{ title or "Flask文件管理" }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" />
  <style>
    /* 右键菜单样式 */
    #context-menu {
      position: absolute;
      min-width: 140px;
      background: white;
      border: 1px solid #ccc;
      border-radius: 4px;
      box-shadow: 2px 2px 6px rgba(0,0,0,0.2);
      display: none;
      z-index: 9999;
      user-select: none;
    }
    #context-menu ul {
      list-style: none;
      margin: 0;
      padding: 5px 0;
    }
    #context-menu ul li {
      padding: 5px 20px;
      cursor: pointer;
    }
    #context-menu ul li:hover {
      background-color: #007bff;
      color: white;
    }
    .file-item:hover {
      background-color: #f8f9fa;
      cursor: pointer;
    }
    /* 拖拽样式 */
    .dragging {
      opacity: 0.5;
    }
  </style>
  <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
  <script src="https://kit.fontawesome.com/a076d05399.js" crossorigin="anonymous"></script>
</head>
<body class="bg-light py-4">
<div class="container">
  {% if messages %}
  <div class="alert alert-warning" role="alert">
    {% for msg in messages %}
      <div>{{ msg }}</div>
    {% endfor %}
  </div>
  {% endif %}

  ''' + body_html + '''

</div>
<script>
$(function() {
  var $menu = $('#context-menu');
  var selectedItem = null;

  /* 右键菜单显示 */
  function showMenu(e, $item) {
    e.preventDefault();
    selectedItem = $item;

    var mouseX = e.pageX;
    var mouseY = e.pageY;

    $menu.css({ top: mouseY + 'px', left: mouseX + 'px', display: 'block' });
  }

  // 右键菜单激活
  $('.file-item').on('contextmenu', function(e) {
    showMenu(e, $(this));
  });

  // 工具按钮调出菜单
  $('.open-menu-btn').on('click', function(e) {
    var $tr = $(this).closest('tr');
    showMenu(e, $tr);
  });

  // 点击隐藏菜单
  $(document).on('click', function(e) {
    if(!$(e.target).closest('#context-menu').length) {
      $menu.hide();
    }
  });

  // 右键菜单 重命名
  $('.context-rename').on('click', function() {
    if(!selectedItem) return;
    var oldName = selectedItem.data('name');
    var oldPath = selectedItem.data('path');

    var newName = prompt('请输入新名称：', oldName);
    if(!newName || newName.trim() === '') {
      $menu.hide();
      return;
    }
    newName = newName.trim();

    $.ajax({
      url: "{{ url_for('rename') }}",
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({old_path: oldPath, new_name: newName}),
      success: function(data) {
        alert(data.message);
        if(data.status === 'success') {
          location.reload();
        }
      },
      error: function() {
        alert('请求失败');
      },
      complete: function() {
        $menu.hide();
      }
    });
  });

  // 右键菜单 删除
  $('.context-delete').on('click', function() {
    if(!selectedItem) return;
    var name = selectedItem.data('name');
    var path = selectedItem.data('path');

    if(!confirm(`确定删除 "${name}"？删除后不可恢复！`)) {
      $menu.hide();
      return;
    }

    $.ajax({
      url: "{{ url_for('delete') }}",
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({path: path}),
      success: function(data) {
        alert(data.message);
        if(data.status === 'success') {
          location.reload();
        }
      },
      error: function() {
        alert('请求失败');
      },
      complete: function() {
        $menu.hide();
      }
    });
  });

  // ----------- 拖拽移动功能 -----------

  var $dragged = null;

  // 拖拽开始
  $('.file-item').on('dragstart', function(e) {
    $dragged = $(this);
    e.originalEvent.dataTransfer.setData('text/plain', 'dummy'); // firefox兼容
    setTimeout(() => $dragged.addClass('dragging'), 0);
  });

  // 拖拽结束
  $('.file-item').on('dragend', function() {
    if ($dragged) $dragged.removeClass('dragging');
    $dragged = null;
  });

  // 允许拖入文件夹作为目标
  $('.file-item[data-is-dir="1"]').on('dragover', function(e) {
    e.preventDefault();
    $(this).addClass('bg-info text-white');
  });

  $('.file-item[data-is-dir="1"]').on('dragleave', function() {
    $(this).removeClass('bg-info text-white');
  });

  // 放下事件
  $('.file-item[data-is-dir="1"]').on('drop', function(e) {
    e.preventDefault();
    $(this).removeClass('bg-info text-white');
    if (!$dragged) return;

    var srcPath = $dragged.data('path');
    var dstDirPath = $(this).data('path');

    // 防止拖进自己或自己子文件夹
    if (dstDirPath === srcPath || dstDirPath.startsWith(srcPath + '/')) {
      alert('不能移动到自己或自己子目录内');
      return;
    }

    $.ajax({
      url: "{{ url_for('move') }}",
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({src_path: srcPath, dst_dir_path: dstDirPath}),
      success: function(data) {
        alert(data.message);
        if(data.status === 'success') {
          location.reload();
        }
      },
      error: function() {
        alert('请求失败');
      }
    });
  });
});
</script>

<div id="context-menu" class="shadow rounded bg-white">
  <ul class="list-unstyled mb-0">
    <li class="context-rename" style="cursor:pointer;">重命名</li>
    <li class="context-delete text-danger" style="cursor:pointer;">删除</li>
  </ul>
</div>

</body>
</html>
'''
    context.setdefault('messages', get_flashed_messages())
    template = Template(base_template)
    return template.render(**context)

# ----------- 路由区 ----------

@app.route('/')
def index():
    # 已登录跳转文件管理，未登录跳转登录页面
    if 'username' in session:
        return redirect(url_for('files'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    """用户注册"""
    body = '''
<h3 class="mb-4">注册</h3>
<form method="post">
  <div class="form-group">
    <label>用户名</label>
    <input type="text" name="username" class="form-control" required>
  </div>
  <div class="form-group">
    <label>密码</label>
    <input type="password" name="password" class="form-control" required>
  </div>
  <button type="submit" class="btn btn-success">注册</button>
  <a href="{{ url_for('login') }}" class="btn btn-link">已有账号？登录</a>
</form>
'''

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash('用户名和密码不能为空')
            return render_template_string(body, title='注册')

        if query_user(username):
            flash('用户名已存在')
            return render_template_string(body, title='注册')

        pwd_hash = generate_password_hash(password)
        success = add_user(username, pwd_hash)
        if not success:
            flash('注册失败，用户名可能已存在')
            return render_template_string(body, title='注册')

        # 为用户建目录
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], username), exist_ok=True)

        flash('注册成功，请登录')
        return redirect(url_for('login'))
    return render_template_string(body, title='注册')

@app.route('/login', methods=['GET','POST'])
def login():
    """用户登录"""
    body = '''
<h3 class="mb-4">登录</h3>
<form method="post">
  <div class="form-group">
    <label>用户名</label>
    <input type="text" name="username" class="form-control" required>
  </div>
  <div class="form-group">
    <label>密码</label>
    <input type="password" name="password" class="form-control" required>
  </div>
  <button type="submit" class="btn btn-primary">登录</button>
  <a href="{{ url_for('register') }}" class="btn btn-link">新用户注册</a>
</form>
'''
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = query_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash('登录成功')
            return redirect(url_for('files'))
        else:
            flash('用户名或密码错误')
    return render_template_string(body, title='登录')

@app.route('/logout')
def logout():
    """登出"""
    session.pop('username', None)
    flash('已退出登录')
    return redirect(url_for('login'))

@app.route('/files', methods=['GET','POST'])
@login_required
def files():
    """文件列表页，支持上传和新建文件夹"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)

    # 当前路径，URL参数 path ，无头尾斜杠
    path = request.args.get('path','').strip('/')
    try:
        current_dir = safe_join(user_base, path)
    except ValueError:
        flash('非法路径访问')
        return redirect(url_for('files'))

    os.makedirs(current_dir, exist_ok=True)

    if request.method == 'POST':
        # 上传文件操作
        if 'file' in request.files:
            f = request.files['file']
            if f.filename == '':
                flash('请选择文件')
                return redirect(request.url)
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                save_path = os.path.join(current_dir, filename)
                f.save(save_path)
                flash(f'文件 "{filename}" 上传成功')
                return redirect(url_for('files', path=path))
            else:
                flash('不允许的文件类型')
                return redirect(request.url)
        # 新建文件夹操作
        elif 'folder_name' in request.form:
            folder_name = request.form.get('folder_name', '').strip()
            if not folder_name:
                flash('文件夹名不能为空')
                return redirect(url_for('files', path=path))
            folder_name = secure_filename(folder_name)
            folder_path = os.path.join(current_dir, folder_name)
            if os.path.exists(folder_path):
                flash('文件夹已存在')
                return redirect(url_for('files', path=path))
            try:
                os.mkdir(folder_path)
                flash(f'文件夹 "{folder_name}" 创建成功')
            except Exception as e:
                flash(f'创建失败: {e}')
            return redirect(url_for('files', path=path))

    # 遍历目录文件夹
    entries = []
    for entry in os.listdir(current_dir):
        entry_path = os.path.join(current_dir, entry)
        entries.append({
            'name': entry,
            'is_dir': os.path.isdir(entry_path),
        })

    # 面包屑导航构造
    crumbs = []
    if path:
        parts = path.split('/')
        for i in range(len(parts)):
            cpath = '/'.join(parts[:i+1])
            crumbs.append({'name': parts[i], 'path': cpath})

    # 页面主体html
    body = '''
<div class="d-flex justify-content-between align-items-center mb-3">
  <h4>用户: {{ session.username }} - 文件管理</h4>
  <a href="{{ url_for('logout') }}" class="btn btn-outline-secondary btn-sm">登出</a>
</div>

<nav aria-label="breadcrumb">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('files') }}">根目录</a></li>
    {% for crumb in crumbs %}
    <li class="breadcrumb-item"><a href="{{ url_for('files', path=crumb.path) }}">{{ crumb.name }}</a></li>
    {% endfor %}
  </ol>
</nav>

<div class="row mb-3">
  <div class="col-md-6">
    <form class="form-inline" method="post" enctype="multipart/form-data">
      <div class="form-group mx-sm-2 mb-2">
        <input type="file" name="file" class="form-control-file" required>
      </div>
      <button type="submit" class="btn btn-primary mb-2">上传文件</button>
    </form>
  </div>
  <div class="col-md-6">
    <form class="form-inline justify-content-end" method="post">
      <div class="form-group mx-sm-2 mb-2">
        <input type="text" name="folder_name" placeholder="新建文件夹" class="form-control" required>
      </div>
      <button type="submit" class="btn btn-success mb-2">新建文件夹</button>
    </form>
  </div>
</div>

<table class="table table-striped table-bordered table-sm">
  <thead class="thead-light">
    <tr><th>名称</th><th>类型</th><th style="width:140px;">操作</th></tr>
  </thead>
  <tbody>
    {% if files %}
      {% for f in files %}
      <tr class="file-item" draggable="true" data-name="{{ f.name }}" data-is-dir="{{ 1 if f.is_dir else 0 }}"
          data-path="{{ (current_path ~ '/' if current_path else '') ~ f.name }}">
        <td>
          {% if f.is_dir %}
            <a href="{{ url_for('files', path=(current_path ~ '/' if current_path else '') ~ f.name) }}">
              <i class="fas fa-folder"></i> {{ f.name }}
            </a>
          {% else %}
            <i class="fas fa-file"></i>
            <a href="{{ url_for('download', filename=(current_path ~ '/' if current_path else '') ~ f.name) }}" target="_blank">{{ f.name }}</a>
          {% endif %}
        </td>
        <td>{{ '文件夹' if f.is_dir else '文件' }}</td>
        <td>
          <button class="btn btn-sm btn-outline-secondary open-menu-btn">操作菜单</button>
        </td>
      </tr>
      {% endfor %}
    {% else %}
      <tr><td colspan="3" class="text-center">空目录</td></tr>
    {% endif %}
  </tbody>
</table>
'''
    return render_template_string(body, title='文件管理', files=entries, crumbs=crumbs, current_path=path, session=session)

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    """文件下载"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    try:
        abs_path = safe_join(user_base, filename)
    except ValueError:
        flash('非法路径访问')
        return redirect(url_for('files'))

    if not os.path.isfile(abs_path):
        flash('文件不存在')
        return redirect(url_for('files'))

    return send_file(abs_path, as_attachment=True)

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    """
    AJAX删除文件或目录
    请求json: {path: 相对路径}
    """
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    data = request.get_json()

    target_path = data.get('path')
    if not target_path:
        return jsonify({'status': 'error', 'message':'未提供路径'})

    try:
        abs_path = safe_join(user_base, target_path)
    except ValueError:
        return jsonify({'status':'error', 'message':'非法路径'})

    if not os.path.exists(abs_path):
        return jsonify({'status':'error', 'message':'路径不存在'})

    try:
        if os.path.isfile(abs_path):
            os.remove(abs_path)
        else:
            import shutil
            shutil.rmtree(abs_path)
        return jsonify({'status':'success', 'message':'删除成功'})
    except Exception as e:
        return jsonify({'status':'error', 'message':f'删除失败: {e}'})

@app.route('/rename', methods=['POST'])
@login_required
def rename():
    """
    AJAX重命名文件或目录
    json: {old_path: 旧相对路径, new_name: 新名称}
    """
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    data = request.get_json()

    old_path = data.get('old_path')
    new_name = data.get('new_name')
    if not old_path or not new_name:
        return jsonify({'status':'error', 'message':'参数不完整'})

    new_name = secure_filename(new_name)

    try:
        abs_old_path = safe_join(user_base, old_path)
    except ValueError:
        return jsonify({'status':'error', 'message':'非法路径'})

    if not os.path.exists(abs_old_path):
        return jsonify({'status':'error', 'message':'源路径不存在'})

    parent_dir = os.path.dirname(abs_old_path)
    abs_new_path = os.path.join(parent_dir, new_name)

    if os.path.exists(abs_new_path):
        return jsonify({'status':'error', 'message':'目标名称已存在'})

    try:
        os.rename(abs_old_path, abs_new_path)
        return jsonify({'status':'success', 'message':'重命名成功'})
    except Exception as e:
        return jsonify({'status':'error', 'message':f'重命名失败: {e}'})

@app.route('/move', methods=['POST'])
@login_required
def move():
    """
    AJAX拖拽移动文件夹/文件
    json: {src_path: 源路径, dst_dir_path: 目标目录路径}
    """
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    data = request.get_json()

    src_path = data.get('src_path')
    dst_dir_path = data.get('dst_dir_path')

    if not src_path or not dst_dir_path:
        return jsonify({'status':'error', 'message':'参数不完整'})

    try:
        abs_src = safe_join(user_base, src_path)
        abs_dst_dir = safe_join(user_base, dst_dir_path)
    except ValueError:
        return jsonify({'status':'error', 'message':'非法路径'})

    if not os.path.exists(abs_src):
        return jsonify({'status':'error', 'message':'源路径不存在'})
    if not os.path.isdir(abs_dst_dir):
        return jsonify({'status':'error', 'message':'目标目录不存在'})

    # 为避免成为自己子目录，禁止移动到自己及其子目录
    if abs_dst_dir == abs_src or abs_dst_dir.startswith(abs_src + os.sep):
        return jsonify({'status':'error', 'message':'不能移动到自己或自己子目录内'})

    dst_path = os.path.join(abs_dst_dir, os.path.basename(abs_src))
    if os.path.exists(dst_path):
        return jsonify({'status':'error', 'message':'目标位置已存在同名文件/文件夹'})

    try:
        os.rename(abs_src, dst_path)
        return jsonify({'status':'success', 'message':'移动成功'})
    except Exception as e:
        return jsonify({'status':'error', 'message':f'移动失败: {e}'})

# ----------- 主程序入口 -----------

if __name__ == '__main__':
    # 启动调试服务器
    app.run(debug=True)
