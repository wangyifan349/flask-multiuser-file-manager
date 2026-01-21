from flask import Flask, request, send_from_directory, abort, jsonify, render_template_string
import os, shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "better-secret"
UPLOAD_ROOT = 'uploads'
os.makedirs(UPLOAD_ROOT, exist_ok=True)   # Ensure upload directory exists

def safe_join(base, *paths):                                              # Prevent directory traversal
    final_path = os.path.abspath(os.path.join(base, *paths))
    if not final_path.startswith(os.path.abspath(base)):
        abort(403)
    return final_path

def make_dir_tree(root_path, rel_path=""):                                # Recursively return all folders as nested dict
    nodes = []
    for item in sorted(os.listdir(root_path)):
        if item.startswith('.'): continue
        abs_item = os.path.join(root_path, item)
        item_rel = os.path.join(rel_path, item).replace("\\", "/")
        if os.path.isdir(abs_item):
            nodes.append({
                "name": item,
                "path": item_rel,
                "children": make_dir_tree(abs_item, item_rel)
            })
    return nodes

@app.route('/')
def index():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Flask File Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body { background: #fffbe7; }
    .golden-card { background: #ffe08a; border: 1px solid #dab700; }
    .golden-btn { background: #dab700 !important; color: #fff !important; }
    #sidebar { min-width: 220px; max-width: 320px; border-right:2px solid #dab700; background: #fffdfa; min-height: 85vh; }
    #file-table tbody tr.selected, .folder-tree li.selected { background: #ffe69c; }
    .folder-tree { list-style: none; padding-left:0; }
    .folder-tree ul { list-style: none; padding-left: 1.2em; }
    .folder-tree li { cursor:pointer; user-select:none; }
    .context-menu { position: fixed; background: #fffbe7; border: 1px solid #dab700; z-index: 50; min-width: 130px; box-shadow: 0 2px 7px #ccc; border-radius: 7px; display: none; font-size:15px; animation: menu-in .07s linear; }
    .context-menu li { padding:8px 20px; cursor:pointer; }
    .context-menu li:hover { background: #fff3cd; }
    @keyframes menu-in { 0%{transform:scale(0.97);} 100%{transform:scale(1);} }
    .folder-ico { color: #c19f21;}
    .file-ico { color: #ad7721;}
    .breadcrumb-golden { --bs-breadcrumb-divider: '▶'; background: #fffbe7; padding:.2rem .5rem; border-radius:5px; font-size:15px; }
    td,th{ vertical-align:middle;}
    </style>
</head>
<body>
<div class="container-fluid mt-4">
    <div class="row">
        <div id="sidebar" class="col-3 px-2">
            <div class="d-flex justify-content-between mb-2">
                <strong style="font-size:18px;">Directories</strong>
                <!-- No "New" button here per user requirement -->
            </div>
            <div style="max-height:77vh; overflow:auto;">
                <ul id="folder-tree" class="folder-tree"></ul>           <!-- Sidebar directory tree -->
            </div>
        </div>
        <div class="col-9">
            <div id="path-breadcrumb" class="breadcrumb-golden mb-2"></div>
            <div class="golden-card p-2 mb-3 border rounded shadow-sm">
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <input type="file" id="input-upload-files" class="form-control form-control-sm" multiple style="max-width:240px;">
                    <button id="btn-upload" class="btn golden-btn btn-sm">Upload</button>
                    <button id="btn-create-folder" class="btn golden-btn btn-sm">New Folder</button>
                </div>
            </div>
            <div class="golden-card p-3 border rounded shadow" style="min-height:55vh;">
                <table id="file-table" class="table align-middle table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Name</th><th>Type</th><th>Action</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<ul id="context-menu" class="context-menu"></ul>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script>
// ---------------------- Frontend Variables ----------------------------
let current_dir_path = "";                      // Current folder path (e.g. "foo/bar")
let dragged_item_path = null;                   // Path of the item being dragged
let dragged_item_type = null;                   // Type ("file"/"folder")
let folder_tree_data = [];                      // Directory tree structure

function reload_sidebar_and_content(focus_path) {                                   // Reload both tree and right pane
    fetch_dir_tree().then(() => {
        render_folder_tree(focus_path!==undefined ? focus_path : current_dir_path);
    });
    fetch_file_list(current_dir_path);
}
function fetch_dir_tree() {
    return $.get("/api/tree", function(data){
        folder_tree_data = data;
    });
}
function fetch_file_list(dir_path) {
    $.get('/api/list', {path:dir_path}, function(resp){
        render_breadcrumb(dir_path);
        render_file_table(resp.dirs, resp.files);
    });
}
function render_breadcrumb(dir_path) {
    let crumbs = [`<span data-bc="">Root</span>`];
    let p = "";
    if(dir_path){
        dir_path.split('/').filter(Boolean).forEach(function(seg){
            p = p ? p + "/" + seg : seg;
            crumbs.push(`<span>▶</span><span data-bc="${p}">${seg}</span>`);
        });
    }
    $('#path-breadcrumb').html(crumbs.join(""));
    $('#path-breadcrumb span[data-bc]').css({"cursor":"pointer", "color":"#be8200"});
    $('#path-breadcrumb span[data-bc]').click(function(){
        let path = $(this).data('bc');
        current_dir_path = path || "";
        fetch_file_list(current_dir_path);
        render_folder_tree(current_dir_path);
    });
}
function render_file_table(dirs, files) {
    const tbody = $("#file-table tbody").empty();
    dirs.forEach(function(name){
        let row = $(`
        <tr class="file-row" draggable="true" data-name="${name}" data-type="folder">
            <td><span class="folder-ico">📁</span> <span class="name-text">${name}</span></td>
            <td>Folder</td>
            <td>
                <a href="#" class="a-delete text-danger me-2">Delete</a>
            </td>
        </tr>`);
        row.find(".name-text").click(function(){
            current_dir_path = current_dir_path ? (current_dir_path + "/" + name) : name;
            fetch_file_list(current_dir_path);
            render_folder_tree(current_dir_path);
        });
        row.find(".a-delete").click(function(){ ajax_delete(current_dir_path + "/" + name); return false; });
        attach_row_events(row, name, "folder", current_dir_path + "/" + name);
        tbody.append(row);
    });
    files.forEach(function(name){
        let row = $(`
        <tr class="file-row" draggable="true" data-name="${name}" data-type="file">
            <td><span class="file-ico">📄</span> <span class="name-text">${name}</span></td>
            <td>File</td>
            <td>
                <a href="/download?path=${encodeURIComponent(current_dir_path ? current_dir_path + "/" + name : name)}" class="text-primary me-2" target="_blank">Download</a>
                <a href="#" class="a-delete text-danger">Delete</a>
            </td>
        </tr>`);
        row.find(".a-delete").click(function(){ ajax_delete(current_dir_path + "/" + name); return false; });
        attach_row_events(row, name, "file", current_dir_path + "/" + name);
        tbody.append(row);
    });
}
function attach_row_events(row, name, type, abs_path) {
    row.on("dragstart", function(e){
        dragged_item_path = abs_path; dragged_item_type = type;
    });
    row.on("dragend", function(e){
        dragged_item_path = null; dragged_item_type = null;
    });
    row.on("dragover", function(e){ e.preventDefault(); }); // Allow folder<=>folder moves: handled on drop
    row.on("drop", function(e){
        if(dragged_item_path && dragged_item_path !== abs_path) {
            if(type === "folder") { // Only allow drop ONTO folders
                ajax_move(dragged_item_path, abs_path);
            }
        }
    });
    row.on("contextmenu", function(e){
        e.preventDefault();
        show_context_menu(e.pageX, e.pageY, name, type, abs_path, row);
    });
}
function ajax_delete(item_path) {
    if(!confirm("Are you sure to delete?")) return;
    $.ajax({
        url: "/api/delete", type:"POST",
        contentType:"application/json",
        data: JSON.stringify({path: item_path}),
        success: function(res){
            if(res.code) alert(res.msg||"Delete failed");
            reload_sidebar_and_content();
        }
    });
}
function ajax_move(src, dst) {
    $.ajax({
        url:"/api/move",type:"POST",
        contentType:"application/json",
        data: JSON.stringify({src:src, dst:dst}),
        success:function(res){
            if(res.code) alert(res.msg);
            reload_sidebar_and_content();
        }
    });
}
function ajax_rename(item_path, old_name, type) {
    let new_name = prompt("Rename:", old_name);
    if(!new_name || new_name === old_name) return;
    let dst_dir = item_path.includes("/") ? item_path.substr(0, item_path.lastIndexOf("/")) : "";
    $.ajax({
        url: "/api/move", type:"POST",
        contentType: "application/json",
        data: JSON.stringify({ src: item_path, dst: dst_dir, new_name: new_name }),
        success: function(res){
            if(res.code){ alert(res.msg); return;}
            reload_sidebar_and_content(dst_dir);
        }
    });
}
function ajax_create_folder(parent_path) {
    let name = prompt("New folder name:");
    if(!name) return;
    $.post("/api/mkdir", {path:parent_path||"", name:name}, function(res){
        if(res.code) alert(res.msg);
        reload_sidebar_and_content(parent_path);
    });
}
function render_folder_tree(highlight_path) {
    $("#folder-tree").empty();
    function _recur(nodes, base_path) {
        let ul = $("<ul>");
        nodes.forEach(function(nd){
            let li = $(`<li><span class="folder-ico">📁</span> <span class="tree-folder-name">${nd.name}</span></li>`);
            let abs = nd.path;
            li.attr("data-path", abs);
            if(abs === highlight_path) li.addClass("selected");
            li.find(".tree-folder-name").click(function(e){
                e.stopPropagation();
                current_dir_path = abs;
                fetch_file_list(current_dir_path);
                render_folder_tree(current_dir_path);
            });
            li.get(0).draggable = true;
            li.on("dragstart", function(){ dragged_item_path = abs; dragged_item_type = "folder"; });
            li.on("dragend", function(){ dragged_item_path = null; dragged_item_type = null; });
            li.on("dragover", function(e){ e.preventDefault(); });
            li.on("drop", function(e){
                if(dragged_item_path && dragged_item_path !== abs) {
                    ajax_move(dragged_item_path, abs);
                }
            });
            li.on("contextmenu", function(e){
                e.preventDefault();
                show_context_menu(e.pageX, e.pageY, nd.name,"folder", abs, li);
            });
            if(nd.children && nd.children.length>0)
                li.append(_recur(nd.children, abs));
            ul.append(li);
        });
        return ul;
    }
    $("#folder-tree").append(_recur(folder_tree_data, ""));
}
function show_context_menu(x, y, name, type, abs_path, jq_elem) {
    hide_context_menu();
    $(".file-row,.folder-tree li").removeClass("selected");
    jq_elem && jq_elem.addClass("selected");
    let menu = $("#context-menu");
    let items = [];
    if(type==="folder"){
        items = [
            {txt:"Rename",cb:()=>{ajax_rename(abs_path, name, type);}},
            {txt:"Delete",cb:()=>{ajax_delete(abs_path);}}
        ];
    } else {
        items = [
            {txt:"Download",cb:()=>{window.open("/download?path="+encodeURIComponent(abs_path));}},
            {txt:"Rename",cb:()=>{ajax_rename(abs_path, name, type);}},
            {txt:"Delete",cb:()=>{ajax_delete(abs_path);}}
        ];
    }
    menu.html(items.map(e=>`<li>${e.txt}</li>`).join(""));
    menu.show().css({left:x, top:y});
    menu.children().each(function(idx, li){
        $(li).click(function(){
            hide_context_menu(); items[idx].cb();
        });
    });
}
function hide_context_menu(){ $("#context-menu").hide();$(".selected").removeClass("selected"); }
$(window).on("click scroll contextmenu", hide_context_menu);

$("#btn-create-folder").click(function(){ ajax_create_folder(current_dir_path); });
$("#btn-upload").click(function() {
    let input = $("#input-upload-files")[0];
    if(!input.files.length) {alert("Please select files!"); return;}
    let fd = new FormData();
    fd.append("path", current_dir_path);
    for(let file of input.files)
        fd.append("files", file);
    $.ajax({
        url:"/api/upload",type:"POST",data:fd,
        contentType:false, processData:false,
        success:function(res){
            if(res.code) alert(res.msg);
            input.value = "";
            reload_sidebar_and_content();
        }
    });
});
$("#input-upload-files").on("change",()=>{});
window.ondragover = window.ondragenter = window.ondragleave = window.ondrop = e=>{e.preventDefault();};
$(function(){
    reload_sidebar_and_content();
});
</script>
</body>
</html>
    """)

@app.route('/api/list')
def api_list():
    dir_rel = request.args.get("path","")
    abs_dir = safe_join(UPLOAD_ROOT, dir_rel)
    if not os.path.exists(abs_dir):
        return jsonify({"code":1, "msg":"Directory not found"})
    dirs = []
    files = []
    for name in sorted(os.listdir(abs_dir)):
        if name.startswith('.'): continue
        p = os.path.join(abs_dir, name)
        if os.path.isdir(p): dirs.append(name)
        else: files.append(name)
    return jsonify({"code":0, "dirs":dirs, "files":files})

@app.route('/api/tree')
def api_tree():
    return jsonify(make_dir_tree(UPLOAD_ROOT,""))

@app.route('/api/upload', methods=['POST'])
def api_upload():
    rel_dir = request.form.get("path","")
    abs_dir = safe_join(UPLOAD_ROOT, rel_dir)
    if not os.path.isdir(abs_dir):
        return jsonify({"code":1,"msg":"Directory does not exist"})
    files = request.files.getlist("files")
    for file in files:
        filename = secure_filename(file.filename)
        file.save(os.path.join(abs_dir, filename))
    return jsonify({"code":0})

@app.route('/api/delete', methods=['POST'])
def api_delete():
    rel_path = request.json.get("path","")
    abs_path = safe_join(UPLOAD_ROOT, rel_path)
    if not os.path.exists(abs_path):
        return jsonify({"code":1,"msg":"Not found"})
    try:
        if os.path.isfile(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            if os.listdir(abs_path):
                shutil.rmtree(abs_path)   # Recursively delete directory
            else:
                os.rmdir(abs_path)
        else:
            return jsonify({"code":1,"msg":"Not found"})
    except Exception as e:
        return jsonify({"code":1,"msg":"Delete failed:"+str(e)})
    return jsonify({'code':0})

@app.route('/api/mkdir', methods=['POST'])
def api_mkdir():
    rel_dir = request.form.get("path","")
    folder_name = request.form.get("name")
    if '/' in folder_name or '\\' in folder_name or not folder_name:
        return jsonify({"code":1, "msg":"Invalid folder name"})
    abs_dir = safe_join(UPLOAD_ROOT, rel_dir, folder_name)
    try:
        os.makedirs(abs_dir)
    except Exception as e:
        return jsonify({"code":1, "msg":"Create failed:"+str(e)})
    return jsonify({'code':0})

@app.route('/api/move', methods=['POST'])
def api_move():
    src_rel = request.json.get("src","")
    dst_rel = request.json.get("dst","")
    new_name = request.json.get("new_name")
    src_abs = safe_join(UPLOAD_ROOT, src_rel)
    dst_abs = safe_join(UPLOAD_ROOT, dst_rel)
    if os.path.abspath(src_abs) == os.path.abspath(dst_abs):
        return jsonify({'code':1,'msg':'Source and destination are the same'})
    if os.path.isdir(src_abs) and os.path.abspath(dst_abs).startswith(os.path.abspath(src_abs)+os.sep):
        return jsonify({'code':1,'msg':'Cannot move into its own subfolder'})
    # Determine target path
    if new_name and new_name != os.path.basename(src_abs):
        target_abs = safe_join(dst_abs, new_name)
    else:
        target_abs = safe_join(dst_abs, os.path.basename(src_abs))
    if os.path.abspath(src_abs) == os.path.abspath(target_abs):
        return jsonify({"code":1, "msg":"Nothing to do"})
    if os.path.exists(target_abs):
        return jsonify({"code":1, "msg":"Target already exists"})
    try:
        shutil.move(src_abs, target_abs)
    except Exception as e:
        return jsonify({'code':1,'msg':'Move failed: '+str(e)})
    return jsonify({'code':0})

@app.route('/download')
def download():
    rel_path = request.args.get('path','')
    abs_path = safe_join(UPLOAD_ROOT, rel_path)
    if not os.path.isfile(abs_path):
        abort(404)
    dir_name, file_name = os.path.split(abs_path)
    return send_from_directory(dir_name, file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
