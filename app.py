"""
Flask 文件管理系统
- SQLite3存储用户账号密码（安全哈希）
- 用户登录注册
- 多级目录文件浏览、上传、下载
- 新建文件夹
- AJAX重命名、删除文件与文件夹
- 拖拽移动文件与文件夹（AJAX异步）
- Bootstrap4 + FontAwesome 美化
- 单文件app.py，内嵌模板和JavaScript
"""

import os
import sqlite3
from flask import (
    Flask, request, session, redirect,
    url_for, flash, jsonify, send_file,
    get_flashed_messages, abort
)
from werkzeug.security import generate_password_hash, check_password_hash  # 密码加密校验
from werkzeug.utils import secure_filename  # 文件名安全化
from functools import wraps  # 装饰器辅助
from jinja2 import Template  # 内嵌模板渲染

# ----------------- 配置部分 -----------------

app = Flask(__name__)
app.secret_key = 'your_secret_key_change_this!'  # Flask会话密钥，生产环境务必替换

UPLOAD_FOLDER = 'uploads'  # 用户文件根目录
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # 确保目录存在
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DATABASE = 'users.db'  # SQLite数据库文件名

# 允许上传的文件扩展名
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'zip', 'rar', 'tar', 'gz'}

# ----------------- 数据库操作 -----------------

def get_db():
    """获取数据库连接，设置Row类型以字典形式访问字段"""
    conn = sqlite3.connect(DATABASE)  # 连接数据库文件
    conn.row_factory = sqlite3.Row  # 结果以字典样式返回
    return conn

def init_db():
    """初始化数据库，建立用户表"""
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,  -- 用户ID
                username TEXT UNIQUE NOT NULL,         -- 用户名（唯一）
                password_hash TEXT NOT NULL            -- 哈希密码
            )
        ''')

def query_user(username: str):
    """查询指定用户名用户，返回Row对象或None"""
    conn = get_db()
    user = conn.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()  # 防SQL注入的参数绑定
    conn.close()
    return user

def add_user(username: str, password_hash: str) -> bool:
    """添加新用户，用户名重复返回False"""
    try:
        conn = get_db()
        conn.execute('INSERT INTO user (username, password_hash) VALUES (?, ?)', (username, password_hash))  # 插入新用户，防注入
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:  # 唯一约束冲突
        return False

init_db()  # 启动时初始化数据库

# ----------------- 工具函数 -----------------

def allowed_file(filename: str) -> bool:
    """判断文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(func):
    """登录状态校验装饰器，未登录跳转登录页"""
    @wraps(func)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated

def safe_join(base: str, *paths: str):
    """
    连接路径，防止目录穿越
    base: 用户主目录
    paths: 子路径（多个）
    """
    base = os.path.abspath(base)
    target = os.path.abspath(os.path.join(base, *paths))  # 拼接绝对路径
    if not target.startswith(base):
        raise ValueError('非法路径访问')
    return target

# ----------------- 模板渲染 -----------------

BASE_TEMPLATE = '''
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>{{ title or "Flask 文件管理" }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" />
  <style>
    #context-menu {
      position: absolute; min-width: 140px; background: white; border: 1px solid #ccc;
      border-radius: 4px; box-shadow: 2px 2px 6px rgba(0,0,0,0.2);
      display: none; z-index: 9999; user-select: none;
    }
    #context-menu ul { list-style: none; margin: 0; padding: 5px 0; }
    #context-menu ul li {
      padding: 5px 20px; cursor: pointer;
    }
    #context-menu ul li:hover {
      background-color: #007bff; color: white;
    }
    .file-item:hover { background-color: #f8f9fa; cursor: pointer; }
    .dragging { opacity: 0.5; }
    .drag-over { background-color: #cce5ff !important; }
  </style>
</head>
<body class="bg-light py-4">
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
      <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
        {{ message }}
        <button type="button" class="close" data-dismiss="alert" aria-label="关闭">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</div>

<div id="context-menu" class="shadow rounded bg-white">
  <ul class="list-unstyled mb-0">
    <li id="context-rename" style="cursor:pointer;">重命名</li>
    <li id="context-delete" class="text-danger" style="cursor:pointer;">删除</li>
  </ul>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js"></script>
<script>
$(function(){
  let $menu = $('#context-menu');
  let $selected = null;

  function showMenu(e, $el) {
    e.preventDefault();
    $selected = $el;
    let x = e.pageX;
    let y = e.pageY;
    $menu.css({top: y + 'px', left: x + 'px'}).show();
  }
  // 右键菜单弹出
  $('.file-item').on('contextmenu', function(e){
    showMenu(e, $(this));
  });
  // 菜单按钮点击弹出
  $('.menu-btn').on('click', function(e){
    e.preventDefault();
    let $el = $(this).closest('tr');
    let offset = $(this).offset();
    $selected = $el;
    $menu.css({top: offset.top + $(this).outerHeight(), left: offset.left}).toggle();
  });
  // 点击空白隐藏菜单
  $(document).on('click', function(e){
    if(!$(e.target).closest('#context-menu').length){
      $menu.hide();
    }
  });

  // 重命名操作
  $('#context-rename').on('click', function(){
    if(!$selected) return;
    let oldName = $selected.data('name');
    let oldPath = $selected.data('path');
    let newName = prompt('请输入新名称：', oldName);
    if(newName === null || newName.trim() === '') {
      $menu.hide(); return;
    }
    newName = newName.trim();
    $.ajax({
      url: "{{ url_for('rename') }}",  // 重命名接口
      method: 'POST',
      contentType:'application/json',
      data: JSON.stringify({old_path: oldPath, new_name: newName}),
      success: function(d){
        alert(d.message);
        if(d.status === 'success') location.reload();
      },
      error: function(){ alert('网络错误'); },
      complete: function(){ $menu.hide(); }
    });
  });

  // 删除操作
  $('#context-delete').on('click', function(){
    if(!$selected) return;
    let name = $selected.data('name');
    let path = $selected.data('path');
    if(!confirm(`确定删除 "${name}"？此操作不可恢复！`)) { $menu.hide(); return; }
    $.ajax({
      url: "{{ url_for('delete') }}",  // 删除接口
      method:'POST',
      contentType:'application/json',
      data: JSON.stringify({path: path}),
      success: function(d){
        alert(d.message);
        if(d.status === 'success') location.reload();
      },
      error: function(){ alert('网络错误'); },
      complete: function(){ $menu.hide(); }
    });
  });

  // 拖拽功能处理
  let $dragged = null;

  $('.file-item').on('dragstart', function(e){
    $dragged = $(this);
    e.originalEvent.dataTransfer.setData('text/plain','dummy'); // 必填以触发drag事件
    setTimeout(() => $dragged.addClass('dragging'), 0);
  });
  $('.file-item').on('dragend', function(){
    if($dragged) $dragged.removeClass('dragging');
    $dragged = null;
  });

  $('.file-item[data-is-dir="1"]').on('dragover', function(e){
    e.preventDefault();
    $(this).addClass('drag-over');
  });
  $('.file-item[data-is-dir="1"]').on('dragleave drop', function(e){
    e.preventDefault();
    $(this).removeClass('drag-over');
  });

  // 目标文件夹放下事件，发送移动请求
  $('.file-item[data-is-dir="1"]').on('drop', function(e){
    e.preventDefault();
    if(!$dragged) return;
    let src_path = $dragged.data('path');
    let dst_dir = $(this).data('path');
    if(dst_dir === src_path || dst_dir.startsWith(src_path + '/')){
      alert('不能移动到自身或子目录');
      return;
    }
    $.ajax({
      url: "{{ url_for('move') }}",  // 移动接口
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({src_path: src_path, dst_dir_path: dst_dir}),
      success: function(d){
        alert(d.message);
        if(d.status === 'success') location.reload();
      },
      error: function(){ alert('网络错误'); }
    });
  });

});
</script>
</body>
</html>
'''

def render_page(body: str, **context):
    """统一渲染页面，嵌入主体HTML"""
    context.setdefault('title', '文件管理系统')
    context.setdefault('body', body)
    template = Template(BASE_TEMPLATE)
    return template.render(**context)

# ----------------- 路由视图 -----------------

@app.route('/')
def route_index():
    """默认首页，登录则跳文件管理，否者登录页"""
    if 'username' in session:
        return redirect(url_for('files'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def route_register():
    """注册视图"""
    body = '''
<h3 class="mb-4">注册</h3>
<form method="post" novalidate>
  <div class="form-group">
    <label for="username">用户名</label>
    <input id="username" type="text" name="username" required class="form-control" />
  </div>
  <div class="form-group">
    <label for="password">密码</label>
    <input id="password" type="password" name="password" required class="form-control" />
  </div>
  <button type="submit" class="btn btn-success">注册</button>
  <a href="{{ url_for('login') }}" class="btn btn-link">已有账号？登录</a>
</form>
'''
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash('用户名和密码不能为空', 'warning')
            return render_page(body, title='注册')
        if query_user(username):
            flash('用户名已存在', 'danger')
            return render_page(body, title='注册')
        pwd_hash = generate_password_hash(password)
        if not add_user(username, pwd_hash):
            flash('注册失败，用户名可能已存在', 'danger')
            return render_page(body, title='注册')
        # 创建用户文件夹
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        os.makedirs(user_folder, exist_ok=True)
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_page(body, title='注册')

@app.route('/login', methods=['GET','POST'])
def route_login():
    """登录视图"""
    body = '''
<h3 class="mb-4">登录</h3>
<form method="post" novalidate>
  <div class="form-group">
    <label for="username">用户名</label>
    <input id="username" type="text" name="username" required class="form-control" />
  </div>
  <div class="form-group">
    <label for="password">密码</label>
    <input id="password" type="password" name="password" required class="form-control" />
  </div>
  <button type="submit" class="btn btn-primary">登录</button>
  <a href="{{ url_for('register') }}" class="btn btn-link">新用户注册</a>
</form>
'''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = query_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash('登录成功', 'success')
            return redirect(url_for('files'))
        else:
            flash('用户名或密码错误', 'danger')
    return render_page(body, title='登录')

@app.route('/logout')
def route_logout():
    """注销登录"""
    session.pop('username', None)
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

@app.route('/files', methods=['GET','POST'])
@login_required
def files():
    """文件浏览、上传、新建文件夹 主视图"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    rel_path = request.args.get('path', '').strip('/')
    try:
        current_dir = safe_join(user_base, rel_path)  # 限制用户访问目录
    except ValueError:
        flash('非法路径访问', 'danger')
        return redirect(url_for('files'))

    os.makedirs(current_dir, exist_ok=True)  # 目录不存在则创建

    if request.method == 'POST':
        # 上传文件
        if 'file' in request.files:
            f = request.files['file']
            if f.filename == '':
                flash('请选择文件', 'warning')
                return redirect(request.url)
            if not allowed_file(f.filename):
                flash('不允许的文件类型', 'danger')
                return redirect(request.url)
            filename = secure_filename(f.filename)
            dst_path = os.path.join(current_dir, filename)
            f.save(dst_path)
            flash(f'文件 "{filename}" 上传成功', 'success')
            return redirect(url_for('files', path=rel_path))
        # 新建文件夹
        elif 'folder_name' in request.form:
            folder_name = request.form.get('folder_name', '').strip()
            if not folder_name:
                flash('文件夹名不能为空', 'warning')
                return redirect(url_for('files', path=rel_path))
            safe_folder_name = secure_filename(folder_name)
            new_folder_path = os.path.join(current_dir, safe_folder_name)
            if os.path.exists(new_folder_path):
                flash('文件夹已存在', 'danger')
                return redirect(url_for('files', path=rel_path))
            try:
                os.mkdir(new_folder_path)
                flash(f'文件夹 "{folder_name}" 创建成功', 'success')
            except Exception as e:
                flash(f'创建失败: {e}', 'danger')
            return redirect(url_for('files', path=rel_path))

    # 列出目录文件
    entries = []
    try:
        for e in sorted(os.listdir(current_dir)):
            abs_e = os.path.join(current_dir, e)
            entries.append({
                'name': e,
                'is_dir': os.path.isdir(abs_e)
            })
    except Exception:
        flash('无法访问当前目录', 'danger')
        entries = []

    # 面包屑导航
    crumbs = []
    if rel_path:
        parts = rel_path.split('/')
        for i in range(len(parts)):
            crumbs.append({
                'name': parts[i],
                'path': '/'.join(parts[:i+1])
            })

    body = '''
<div class="d-flex justify-content-between align-items-center mb-3">
  <h4>用户：{{ session.username }} - 文件管理</h4>
  <a href="{{ url_for('logout') }}" class="btn btn-outline-secondary btn-sm">登出</a>
</div>

<nav aria-label="breadcrumb">
  <ol class="breadcrumb">
    <li class="breadcrumb-item"><a href="{{ url_for('files') }}">根目录</a></li>
    {% for c in crumbs %}
      <li class="breadcrumb-item"><a href="{{ url_for('files', path=c.path) }}">{{ c.name }}</a></li>
    {% endfor %}
  </ol>
</nav>

<div class="row mb-3">
  <div class="col-md-6">
    <form method="post" enctype="multipart/form-data" class="form-inline">
      <input type="file" name="file" required class="form-control-file mr-2" />
      <button type="submit" class="btn btn-primary">上传文件</button>
    </form>
  </div>
  <div class="col-md-6">
    <form method="post" class="form-inline justify-content-end">
      <input type="text" name="folder_name" required placeholder="新建文件夹" class="form-control mr-2" />
      <button type="submit" class="btn btn-success">新建文件夹</button>
    </form>
  </div>
</div>

<table class="table table-sm table-bordered table-striped">
<thead class="thead-light">
  <tr><th>名称</th><th>类型</th><th style="width:160px;">操作</th></tr>
</thead>
<tbody>
{% if files %}
  {% for f in files %}
  <tr class="file-item" draggable="true"
      data-name="{{ f.name }}"
      data-path="{{ (current_path + '/' if current_path else '') + f.name }}"
      data-is-dir="{{ 1 if f.is_dir else 0 }}">
    <td>
      {% if f.is_dir %}
        <a href="{{ url_for('files', path=(current_path + '/' if current_path else '') + f.name) }}">
          <i class="fas fa-folder"></i> {{ f.name }}
        </a>
      {% else %}
        <i class="fas fa-file"></i>
        <a href="{{ url_for('download', filename=(current_path + '/' if current_path else '') + f.name) }}" target="_blank">{{ f.name }}</a>
      {% endif %}
    </td>
    <td>{{ '文件夹' if f.is_dir else '文件' }}</td>
    <td>
      <button class="btn btn-sm btn-outline-secondary menu-btn">菜单</button>
    </td>
  </tr>
  {% endfor %}
{% else %}
  <tr><td colspan="3" class="text-center text-muted">空目录</td></tr>
{% endif %}
</tbody>
</table>
'''
    return render_page(body,
        title='文件管理',
        session=session,
        files=entries,
        crumbs=crumbs,
        current_path=rel_path
    )

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    """文件下载"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    try:
        abs_path = safe_join(user_base, filename)
    except ValueError:
        flash('非法路径访问', 'danger')
        return redirect(url_for('files'))
    if not os.path.isfile(abs_path):
        flash('文件不存在', 'warning')
        return redirect(url_for('files'))
    return send_file(abs_path, as_attachment=True)

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    """AJAX删除文件或文件夹"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    data = request.get_json()
    path = data.get('path')
    if not path:
        return jsonify({'status':'error', 'message':'未提供路径'})
    try:
        abs_path = safe_join(user_base, path)
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
    """AJAX重命名文件或文件夹"""
    username = session['username']
    user_base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    data = request.get_json()
    old_path = data.get('old_path')
    new_name = data.get('new_name')
    if not old_path or not new_name:
        return jsonify({'status':'error', 'message':'参数不完整'})
    new_name = secure_filename(new_name)
    try:
        abs_old = safe_join(user_base, old_path)
    except ValueError:
        return jsonify({'status':'error', 'message':'非法路径'})
    if not os.path.exists(abs_old):
        return jsonify({'status':'error', 'message':'原路径不存在'})
    abs_parent = os.path.dirname(abs_old)
    abs_new = os.path.join(abs_parent, new_name)
    if os.path.exists(abs_new):
        return jsonify({'status':'error', 'message':'目标名已存在'})
    try:
        os.rename(abs_old, abs_new)
        return jsonify({'status':'success', 'message':'重命名成功'})
    except Exception as e:
        return jsonify({'status':'error', 'message':f'重命名失败: {e}'})

@app.route('/move', methods=['POST'])
@login_required
def move():
    """AJAX拖拽移动文件夹/文件"""
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
    if abs_dst_dir == abs_src or abs_dst_dir.startswith(abs_src + os.sep):
        return jsonify({'status':'error', 'message':'不能移动到自身或子目录'})
    new_path = os.path.join(abs_dst_dir, os.path.basename(abs_src))
    if os.path.exists(new_path):
        return jsonify({'status':'error', 'message':'目标目录已有同名文件或文件夹'})
    try:
        os.rename(abs_src, new_path)
        return jsonify({'status':'success', 'message':'移动成功'})
    except Exception as e:
        return jsonify({'status':'error', 'message':f'移动失败: {e}'})

if __name__ == '__main__':
    app.run(debug=True)  # 开发调试模式，生产环境请关闭debug
