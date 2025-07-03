import os  # 操作系统路径管理
import shutil  # 文件移动
from flask import Flask, render_template_string, redirect, url_for, request, flash, \
    send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy  # 数据库
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin  # 登录管理
from werkzeug.security import generate_password_hash, check_password_hash  # 密码加密
from werkzeug.utils import secure_filename  # 文件名安全处理

BASE_DIR = os.path.abspath(os.path.dirname(__file__))  # 项目根目录
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')  # 文件上传目录
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # 确保文件夹存在

app = Flask(__name__)
app.secret_key = 'secret-key-change-this'  # 密钥，生产请换复杂值
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'users.db')  # 数据库路径
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 上传最大50MB

db = SQLAlchemy(app)  # 初始化数据库
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 未登录重定向登录页

# 用户模型，集成UserMixin，实现Flask-Login接口
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 用户ID，主键
    username = db.Column(db.String(150), unique=True)  # 用户名唯一
    password_hash = db.Column(db.String(150))  # 密码哈希

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # 加密存密码

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)  # 校验密码

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # 根据用户ID加载用户对象

@app.before_first_request
def create_db():
    db.create_all()  # 创建数据库表，第一次请求前执行

# 限制路径不能越界uploads目录，防止访问服务器其他文件
def secure_path(path):
    safe_path = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], path))  # 规范路径
    if not safe_path.startswith(app.config['UPLOAD_FOLDER']):
        raise ValueError('非法路径')  # 路径越界抛错
    return safe_path

# 注册页，支持GET/POST
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # 已登录跳主页
    if request.method == 'POST':
        username = request.form.get('username').strip()  # 获取用户名
        password = request.form.get('password').strip()  # 获取密码
        if not username or not password:
            flash('用户名和密码不能为空', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template_string(register_html)  # 渲染注册模板

# 登录页，支持GET/POST
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # 已登录跳主页
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('登录成功', 'success')
            return redirect(url_for('index'))
        flash('用户名或密码错误', 'danger')
    return render_template_string(login_html)  # 渲染登录模板

# 退出登录
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

# 主页面，路径默认为空字符串，支持层级目录浏览
@app.route('/', defaults={'req_path': ''})
@app.route('/<path:req_path>')
@login_required
def index(req_path):
    try:
        abs_path = secure_path(req_path)  # 规范并限制路径
    except ValueError:
        flash('非法路径请求', 'danger')
        return redirect(url_for('index'))

    if not os.path.exists(abs_path):
        flash('路径不存在', 'danger')
        return redirect(url_for('index'))

    if os.path.isfile(abs_path):
        directory = os.path.dirname(abs_path)
        filename = os.path.basename(abs_path)
        return send_from_directory(directory, filename, as_attachment=True)  # 下载文件

    files = []
    dirs = []
    for f in sorted(os.listdir(abs_path)):  # 读取目录排序
        full_path = os.path.join(abs_path, f)
        if os.path.isdir(full_path):
            dirs.append(f)  # 目录列表
        else:
            files.append(f)  # 文件列表

    parent_path = os.path.relpath(os.path.join(abs_path, '..'), app.config['UPLOAD_FOLDER'])
    if parent_path == '.':
        parent_path = ''  # 根目录无上层

    return render_template_string(index_html, files=files, dirs=dirs,
                                  current_path=req_path,
                                  parent_path=parent_path,
                                  user=current_user)

# 上传文件接口
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    dir_path = request.form.get('dir_path', '')
    try:
        abs_dir = secure_path(dir_path)
    except ValueError:
        return jsonify({'error': '非法路径'}), 400

    if 'file' not in request.files:
        return jsonify({'error': '无文件上传'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名不能为空'}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join(abs_dir, filename)
    file.save(save_path)
    return jsonify({'msg': '上传成功', 'filename': filename})

# 删除文件或空文件夹接口
@app.route('/delete', methods=['POST'])
@login_required
def delete():
    path = request.json.get('path', '')
    if not path:
        return jsonify({'error': '未指定路径'}), 400
    try:
        abs_path = secure_path(path)
    except ValueError:
        return jsonify({'error': '非法路径'}), 400

    if not os.path.exists(abs_path):
        return jsonify({'error': '路径不存在'}), 400

    try:
        if os.path.isfile(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            if not os.listdir(abs_path):
                os.rmdir(abs_path)
            else:
                return jsonify({'error': '文件夹非空，无法删除'}), 400
        else:
            return jsonify({'error': '未知文件类型'}), 400
    except Exception as e:
        return jsonify({'error': f'删除失败: {str(e)}'}), 500
    return jsonify({'msg': '删除成功'})

# 创建文件夹接口
@app.route('/mkdir', methods=['POST'])
@login_required
def mkdir():
    dir_path = request.json.get('dir_path', '')
    folder_name = request.json.get('folder_name', '').strip()
    if not folder_name:
        return jsonify({'error': '文件夹名不能为空'}), 400

    try:
        abs_dir = secure_path(dir_path)
    except ValueError:
        return jsonify({'error': '非法路径'}), 400

    new_folder = os.path.join(abs_dir, secure_filename(folder_name))
    if os.path.exists(new_folder):
        return jsonify({'error': '文件夹已存在'}), 400

    try:
        os.mkdir(new_folder)
    except Exception as e:
        return jsonify({'error': f'创建失败: {str(e)}'}), 500

    return jsonify({'msg': '创建成功'})

# 移动文件/目录接口（拖拽操作）
@app.route('/move', methods=['POST'])
@login_required
def move():
    src = request.json.get('src')
    dst_dir = request.json.get('dst_dir')
    if not src or not dst_dir:
        return jsonify({'error': '参数不足'}), 400
    try:
        abs_src = secure_path(src)
        abs_dst_dir = secure_path(dst_dir)
    except ValueError:
        return jsonify({'error': '非法路径'}), 400

    if not os.path.exists(abs_src) or not os.path.isdir(abs_dst_dir):
        return jsonify({'error': '源或目标路径不存在或不合法'}), 400

    filename = os.path.basename(abs_src)
    abs_dst = os.path.join(abs_dst_dir, filename)

    if os.path.exists(abs_dst):
        return jsonify({'error': '目标目录已有同名文件/文件夹'}), 400

    try:
        shutil.move(abs_src, abs_dst)
    except Exception as e:
        return jsonify({'error': f'移动失败: {str(e)}'}), 500

    return jsonify({'msg': '移动成功'})

# ----------- 模板部分 ，使用render_template_string渲染 ------------

# 基础模板，顶部导航，Bootstrap4样式，右键菜单，消息提示
base_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{{ title or "文件管理器" }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet" />
<style>
  body { margin: 20px; }
  #file-list li { margin: 5px 0; cursor: pointer; }
  #file-list li.drag-over { background-color: #d7ebff !important; }
  #context-menu { position:absolute; background:#f8f9fa; border:1px solid #ccc; padding:5px; border-radius:4px; display:none; z-index:1000; width:100px; }
  #context-menu ul { list-style:none; margin:0; padding:0; }
  #context-menu li { padding:5px 10px; cursor:pointer; }
  #context-menu li:hover { background-color:#007bff; color:white; }
  .folder { font-weight:700; color:#2c7be5 !important; }
  .file { color:#555 !important; }
</style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-light mb-3">
  <a class="navbar-brand" href="{{ url_for('index') }}">文件管理器</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto"></ul>
    <ul class="navbar-nav">
    {% if current_user.is_authenticated %}
      <li class="nav-item"><span class="nav-link">欢迎, {{ current_user.username }}</span></li>  {# 用户名显示 #}
      <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">退出</a></li>  {# 退出链接 #}
    {% else %}
      <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">登录</a></li>
      <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">注册</a></li>
    {% endif %}
    </ul>
  </div>
</nav>

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
  {% block content %}{% endblock %}
</div>

<div id="context-menu">
  <ul>
    <li id="cm-delete">删除</li>
  </ul>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js"></script>
<script>
{{ script | safe }}
</script>

</body>
</html>
'''

# 首页模板，展示文件夹和文件，上传，创建文件夹，拖拽移动和右键删除均在页面脚本处理
index_html = '''
{% extends base_html %}
{% block content %}
<h3>当前位置: /{{ current_path or "" }}</h3>  {# 当前路径 #}

<div class="mb-2">
  {% if current_path %}
    <a href="{{ url_for('index', req_path=parent_path) }}" class="btn btn-secondary btn-sm">⬆ 上级目录</a>  {# 上级目录按钮 #}
  {% endif %}
</div>

<div class="row mb-3">
  <div class="col-md-6">
    <form id="upload-form" enctype="multipart/form-data" class="form-inline">  {# 上传表单 #}
      <input type="file" name="file" id="upload-file" class="form-control-file mr-2" required />
      <input type="hidden" name="dir_path" value="{{ current_path }}" />
      <button type="submit" class="btn btn-success">上传</button>
    </form>
  </div>
  <div class="col-md-6">
    <form id="mkdir-form" class="form-inline justify-content-end">  {# 新建目录表单 #}
      <input type="text" id="mkdir-name" placeholder="新建文件夹名" class="form-control mr-2" required />
      <button type="submit" class="btn btn-primary">新建文件夹</button>
    </form>
  </div>
</div>

<ul id="file-list" class="list-group">  {# 文件列表容器 #}
  {% for d in dirs %}
  {% set path_str = current_path + '/' + d if current_path else d %}
  <li class="list-group-item folder" data-path="{{ path_str }}" draggable="true">
    <i class="fas fa-folder"></i>
    <a href="{{ url_for('index', req_path=path_str) }}">{{ d }}</a>
  </li>
  {% endfor %}

  {% for f in files %}
  {% set path_str = current_path + '/' + f if current_path else f %}
  <li class="list-group-item file" data-path="{{ path_str }}" draggable="true">
    <i class="far fa-file"></i>
    <a href="{{ url_for('index', req_path=path_str) }}">{{ f }}</a>
  </li>
  {% endfor %}

  {% if dirs|length == 0 and files|length == 0 %}
  <li class="list-group-item text-muted">该目录为空</li>  {# 空目录提示 #}
  {% endif %}
</ul>

<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet" />  {# 引入Fontawesome图标 #}
{% endblock %}
'''

# 登录页面模板
login_html = '''
{% extends base_html %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <h2 class="mb-4 text-center">登录</h2>
    <form method="POST" novalidate>
      <div class="form-group">
        <label for="username">用户名</label>
        <input required type="text" class="form-control" id="username" name="username" placeholder="请输入用户名" />
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input required type="password" class="form-control" id="password" name="password" placeholder="请输入密码" />
      </div>
      <button type="submit" class="btn btn-primary btn-block">登录</button>
    </form>
    <p class="mt-3 text-center">没有账号？ <a href="{{ url_for('register') }}">注册</a></p>
  </div>
</div>
{% endblock %}
'''

# 注册页面模板
register_html = '''
{% extends base_html %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <h2 class="mb-4 text-center">注册</h2>
    <form method="POST" novalidate>
      <div class="form-group">
        <label for="username">用户名</label>
        <input required type="text" class="form-control" id="username" name="username" placeholder="请输入用户名" />
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input required type="password" class="form-control" id="password" name="password" placeholder="请输入密码" />
      </div>
      <button type="submit" class="btn btn-primary btn-block">注册</button>
    </form>
    <p class="mt-3 text-center">已有账号？ <a href="{{ url_for('login') }}">登录</a></p>
  </div>
</div>
{% endblock %}
'''

# 页面交互的JS脚本，包含上传、新建目录、删除、拖拽移动
script = '''
// 文件上传事件监听
$('#upload-form').on('submit', function(e){
    e.preventDefault();
    var formData = new FormData(this);
    $.ajax({
        url: '/upload',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(res){
            alert(res.msg);
            location.reload();
        },
        error: function(xhr){
            alert(xhr.responseJSON.error || '上传失败');
        }
    });
});

// 新建文件夹事件监听
$('#mkdir-form').on('submit', function(e){
    e.preventDefault();
    var folder_name = $('#mkdir-name').val();
    var dir_path = $('input[name="dir_path"]').val();
    if(!folder_name.trim()){
        alert('文件夹名不能为空');
        return;
    }
    $.ajax({
        url: '/mkdir',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            folder_name: folder_name,
            dir_path: dir_path
        }),
        success: function(res){
            alert(res.msg);
            location.reload();
        },
        error: function(xhr){
            alert(xhr.responseJSON.error || '创建失败');
        }
    });
});

// 右键菜单显示及删除操作
var $menu = $('#context-menu');
var targetPath = '';

$('#file-list').on('contextmenu', 'li', function(e){
    e.preventDefault();
    targetPath = $(this).data('path');
    $menu.css({top: e.pageY + 'px', left: e.pageX + 'px'}).show();
});

$(document).click(function(){
    $menu.hide();
});

$('#cm-delete').click(function(){
    if(!confirm('确定删除此项？')) return;
    $.ajax({
        url: '/delete',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({path: targetPath}),
        success: function(res){
            alert(res.msg);
            location.reload();
        },
        error: function(xhr){
            alert(xhr.responseJSON.error || '删除失败');
        }
    });
});

// 拖拽事件处理
var dragSrcPath = null;

$('#file-list').on('dragstart', 'li', function(e){
    dragSrcPath = $(this).data('path');
    e.originalEvent.dataTransfer.setData('text/plain', dragSrcPath);
    $(this).css('opacity', '0.5');
});

$('#file-list').on('dragend', 'li', function(e){
    $(this).css('opacity', '1');
    dragSrcPath = null;
});

$('#file-list').on('dragover', 'li.folder', function(e){
    e.preventDefault();
    $(this).addClass('drag-over');
});

$('#file-list').on('dragleave drop', 'li.folder', function(e){
    e.preventDefault();
    $(this).removeClass('drag-over');
});

$('#file-list').on('drop', 'li.folder', function(e){
    e.preventDefault();
    var dstDir = $(this).data('path');
    if(dragSrcPath === dstDir) {
        alert('不能移动到自身');
        return;
    }
    $.ajax({
        url: '/move',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({src: dragSrcPath, dst_dir: dstDir}),
        success: function(res){
            alert(res.msg);
            location.reload();
        },
        error: function(xhr){
            alert(xhr.responseJSON.error || '移动失败');
        }
    });
});
'''

# 注入公共模板变量和脚本到所有模板
@app.context_processor
def inject_base():
    return dict(base_html=base_html, script=script)

if __name__ == '__main__':
    app.run(debug=True)
