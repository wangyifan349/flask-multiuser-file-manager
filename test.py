from flask import Flask, request, send_from_directory, abort, jsonify, render_template_string
import os, shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "better-secret"
UPLOAD_ROOT = 'uploads'
os.makedirs(UPLOAD_ROOT, exist_ok=True)   # Ensure upload directory exists

def safe_join(base, *paths):                                          # Safely join paths to prevent directory traversal
    final_path = os.path.abspath(os.path.join(base, *paths))          # Get absolute target path
    if not final_path.startswith(os.path.abspath(base)):              # Ensure it stays inside base
        abort(403)
    return final_path

def make_dir_tree(root_path, rel_path=""):                            # Recursively construct directory tree as nested dict/list
    nodes = []
    for item in sorted(os.listdir(root_path)):
        if item.startswith('.'): continue                             # Skip hidden files/folders
        abs_item = os.path.join(root_path, item)
        item_rel = os.path.join(rel_path, item).replace("\\", "/")    # Platform independent
        if os.path.isdir(abs_item):                                   # If folder, recursively add children
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
                <strong style="font-size:18px;">Directories</strong>      <!-- Sidebar title -->
                <button id="btn-create-root-folder" class="btn golden-btn btn-sm" title="Create folder in root">New</button>
            </div>
            <div style="max-height:77vh; overflow:auto;">
                <ul id="folder-tree" class="folder-tree"></ul>           <!-- Sidebar directory tree -->
            </div>
        </div>
        <div class="col-9">
            <div id="path-breadcrumb" class="breadcrumb-golden mb-2"></div>  <!-- Breadcrumbs -->
            <div class="golden-card p-2 mb-3 border rounded shadow-sm">
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <input type="file" id="input-upload-files" class="form-control form-control-sm" multiple style="max-width:240px;">  <!-- Multi-file upload -->
                    <button id="btn-upload" class="btn golden-btn btn-sm">Upload</button>
                    <button id="btn-create-folder" class="btn golden-btn btn-sm">New Folder</button>
                </div>
            </div>
            <div class="golden-card p-3 border rounded shadow" style="min-height:55vh;">
                <table id="file-table" class="table align-middle table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Name</th><th>Type</th><th>Action</th>     <!-- Table headers -->
                        </tr>
                    </thead>
                    <tbody>
                        <!-- File and folder content -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<ul id="context-menu" class="context-menu"></ul>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script>
// ---------------------- Frontend Variables ----------------------------
let currentDirPath = "";                       // Current folder path (e.g. "foo/bar")
let draggedItemPath = null;                    // Path of the item being dragged
let draggedRowType = null;                     // Type ("file"/"folder") of item being dragged
let folderTreeData = [];                       // Directory tree data structure

function reloadSidebarAndContent(focusPath) {                                   // Reload sidebar and right content pane
    fetchDirTree().then(() => {
        renderFolderTree(focusPath!==undefined ? focusPath : currentDirPath);
    });
    fetchFileList(currentDirPath);
}
function fetchDirTree() {                                                        // Get folder tree data from server
    return $.get("/api/tree", function(data){
        folderTreeData = data;
    });
}
function fetchFileList(dirPath) {                                               // Get folder/file listing for current folder
    $.get('/api/list', {path:dirPath}, function(resp){
        renderBreadcrumb(dirPath);
        renderFileTable(resp.dirs, resp.files);
    });
}
function renderBreadcrumb(dirPath) {                                            // Render top breadcrumb navigation
    let crumbs = [`<span data-bc="">Root</span>`];
    let p = "";
    if(dirPath){
        dirPath.split('/').filter(Boolean).forEach(function(seg){
            p = p ? p + "/" + seg : seg;
            crumbs.push(`<span>▶</span><span data-bc="${p}">${seg}</span>`);
        });
    }
    $('#path-breadcrumb').html(crumbs.join(""));
    $('#path-breadcrumb span[data-bc]').css({"cursor":"pointer", "color":"#be8200"});
    $('#path-breadcrumb span[data-bc]').click(function(){
        let path = $(this).data('bc');              // Go to folder if breadcrumb clicked
        currentDirPath = path || "";
        fetchFileList(currentDirPath);
        renderFolderTree(currentDirPath);
    });
}
function renderFileTable(dirs, files) {                                         // Render right-side file list table
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
            currentDirPath = currentDirPath ? (currentDirPath + "/" + name) : name;      // Enter folder on name click
            fetchFileList(currentDirPath);
            renderFolderTree(currentDirPath);
        });
        row.find(".a-delete").click(function(){ ajaxDelete(currentDirPath+"/"+name); return false; });   // AJAX delete call
        attachRowEvents(row, name, "folder", currentDirPath + "/" + name);             // Attach drag/drop and context menu
        tbody.append(row);
    });
    files.forEach(function(name){
        let row = $(`
        <tr class="file-row" draggable="true" data-name="${name}" data-type="file">
            <td><span class="file-ico">📄</span> <span class="name-text">${name}</span></td>
            <td>File</td>
            <td>
                <a href="/download?path=${encodeURIComponent(currentDirPath ? currentDirPath + "/" + name : name)}" class="text-primary me-2" target="_blank">Download</a>
                <a href="#" class="a-delete text-danger">Delete</a>
            </td>
        </tr>`);
        row.find(".a-delete").click(function(){ ajaxDelete(currentDirPath+"/"+name); return false; });   // AJAX delete call
        attachRowEvents(row, name, "file", currentDirPath + "/" + name);
        tbody.append(row);
    });
}
function attachRowEvents(row, name, type, absPath) {                           // Attach drag & drop and context menu to row
    row.on("dragstart", function(e){
        draggedItemPath = absPath; draggedRowType = type;                      // Start drag
    });
    row.on("dragend", function(e){
        draggedItemPath = null; draggedRowType=null;                           // End drag
    });
    row.on("dragover", function(e){
        if(type==="folder") e.preventDefault();                                // Allow drop on folders only
    });
    row.on("drop", function(e){
        if(type==="folder" && draggedItemPath && draggedItemPath!==absPath){
            ajaxMove(draggedItemPath, absPath);                                // AJAX move
        }
    });
    row.on("contextmenu", function(e){
        e.preventDefault();
        showContextMenu(e.pageX,e.pageY,name,type,absPath,row);                // Show context menu on right click
    });
}
function ajaxDelete(itemPath) {                                                // AJAX delete file/folder
    if(!confirm("Are you sure to delete?")) return;
    $.ajax({
        url: "/api/delete", type:"POST",
        contentType:"application/json",
        data: JSON.stringify({path: itemPath}),
        success: function(res){
            if(res.code) alert(res.msg||"Delete failed");
            reloadSidebarAndContent();
        }
    });
}
function ajaxMove(src, dst){                                                   // AJAX move/rename file/folder
    $.ajax({
        url:"/api/move",type:"POST",
        contentType:"application/json",
        data:JSON.stringify({src:src, dst:dst}),
        success:function(res){
            if(res.code) alert(res.msg);
            reloadSidebarAndContent();
        }
    });
}
function ajaxRename(itemPath, oldName, type){                                  // AJAX rename logic (by move)
    let newName = prompt("Rename:", oldName);
    if(!newName || newName===oldName) return;
    let dstDir = itemPath.substr(0, itemPath.lastIndexOf("/"));
    let dstPath = dstDir ? dstDir + "/" + newName : newName;
    $.ajax({
        url:"/api/move",type:"POST",
        contentType:"application/json",
        data: JSON.stringify({src:itemPath, dst:dstDir}),
        success: function(res){
            if(res.code){ alert(res.msg); return;}
            if(type==="folder") renderFolderTree(dstDir);
            reloadSidebarAndContent(dstDir);
        }
    });
}
function ajaxCreateFolder(parentPath){                                         // AJAX create folder
    let name = prompt("New folder name:");
    if(!name) return;
    $.post("/api/mkdir", {path:parentPath||"", name:name}, function(res){
        if(res.code) alert(res.msg);
        reloadSidebarAndContent(parentPath);
    });
}
function renderFolderTree(highlightPath) {                                 // Render the directory tree recursively
    $("#folder-tree").empty();
    function _recur(nodes, basePath) {
        let ul = $("<ul>");
        nodes.forEach(function(nd){
            let li = $(`<li><span class="folder-ico">📁</span> <span class="tree-folder-name">${nd.name}</span></li>`);
            let abs = nd.path;
            li.attr("data-path", abs);
            if(abs===highlightPath) li.addClass("selected");
            li.find(".tree-folder-name").click(function(e){
                e.stopPropagation();
                currentDirPath = abs;                                            // Change directory on click
                fetchFileList(currentDirPath);
                renderFolderTree(currentDirPath);
            });
            li.get(0).draggable = true;
            li.on("dragstart", function(){ draggedItemPath=abs; draggedRowType="folder"; });
            li.on("dragend", function(){ draggedItemPath=null; draggedRowType=null;});
            li.on("dragover", function(e){e.preventDefault();});
            li.on("drop", function(e){
                if(draggedItemPath && draggedItemPath!==abs){
                    ajaxMove(draggedItemPath, abs);                              // Move dragged item here
                }
            });
            li.on("contextmenu", function(e){
                e.preventDefault();
                showContextMenu(e.pageX,e.pageY, nd.name,"folder", abs, li);     // Show context menu for right click
            });
            if(nd.children && nd.children.length>0)
                li.append(_recur(nd.children, abs));
            ul.append(li);
        });
        return ul;
    }
    $("#folder-tree").append(_recur(folderTreeData, ""));
}
function showContextMenu(x, y, name, type, absPath, jqElem){                // Show right click context menu
    hideContextMenu();
    $(".file-row,.folder-tree li").removeClass("selected");
    jqElem&&jqElem.addClass("selected");
    let menu = $("#context-menu");
    let items = [];
    if(type==="folder"){
        items = [
            {txt:"New Subfolder",cb:()=>{ajaxCreateFolder(absPath);}},
            {txt:"Upload Here",cb:()=>{currentDirPath=absPath;fetchFileList(absPath);$("#input-upload-files").click();}},
            {txt:"Rename",cb:()=>{ajaxRename(absPath, name, type);}},
            {txt:"Delete",cb:()=>{ajaxDelete(absPath);}}
        ];
    } else {
        items = [
            {txt:"Download",cb:()=>{window.open("/download?path="+encodeURIComponent(absPath));}},
            {txt:"Rename",cb:()=>{ajaxRename(absPath, name, type);}},
            {txt:"Delete",cb:()=>{ajaxDelete(absPath);}}
        ];
    }
    menu.html(items.map(e=>`<li>${e.txt}</li>`).join(""));
    menu.show().css({left:x, top:y});
    menu.children().each(function(idx, li){
        $(li).click(function(){
            hideContextMenu(); items[idx].cb();
        });
    });
}
function hideContextMenu(){ $("#context-menu").hide();$(".selected").removeClass("selected"); }
$(window).on("click scroll contextmenu", hideContextMenu);

$("#btn-create-root-folder").click(function(){ ajaxCreateFolder(""); });         // "New" on root: create folder in root
$("#btn-create-folder").click(function(){ ajaxCreateFolder(currentDirPath); });  // "New Folder" button: create in current folder
$("#btn-upload").click(function(){
    let input = $("#input-upload-files")[0];
    if(!input.files.length) {alert("Please select files!"); return;}
    let fd = new FormData();
    fd.append("path", currentDirPath);
    for(let file of input.files)
        fd.append("files", file);
    $.ajax({
        url:"/api/upload",type:"POST",data:fd,
        contentType:false, processData:false,
        success:function(res){
            if(res.code) alert(res.msg);
            input.value = "";
            reloadSidebarAndContent();
        }
    });
});
$("#input-upload-files").on("change",()=>{}); // disables default reload on upload
window.ondragover = window.ondragenter = window.ondragleave = window.ondrop = e=>{e.preventDefault();}; // Prevent default browser drag
$(function(){
    reloadSidebarAndContent();      // Initial load
});
</script>
</body>
</html>
    """)

@app.route('/api/list')
def api_list():
    dir_rel = request.args.get("path","")                                 # Relative directory path from query
    abs_dir = safe_join(UPLOAD_ROOT, dir_rel)
    if not os.path.exists(abs_dir):                                       # If path doesn't exist, error
        return jsonify({"code":1, "msg":"Directory not found"})
    dirs = []
    files = []
    for name in sorted(os.listdir(abs_dir)):
        if name.startswith('.'): continue
        p = os.path.join(abs_dir, name)
        if os.path.isdir(p): dirs.append(name)
        else: files.append(name)
    return jsonify({"code":0, "dirs":dirs, "files":files})                # Return arrays of subdirectories & files

@app.route('/api/tree')
def api_tree():
    return jsonify(make_dir_tree(UPLOAD_ROOT,""))                         # Return recursive directory tree

@app.route('/api/upload', methods=['POST'])
def api_upload():
    rel_dir = request.form.get("path","")                                 # Get directory to upload into
    abs_dir = safe_join(UPLOAD_ROOT, rel_dir)
    if not os.path.isdir(abs_dir):                                        # Check directory exists
        return jsonify({"code":1,"msg":"Directory does not exist"})
    files = request.files.getlist("files")
    for file in files:                                                    # Save all uploaded files
        filename = secure_filename(file.filename)
        file.save(os.path.join(abs_dir, filename))
    return jsonify({"code":0})

@app.route('/api/delete', methods=['POST'])
def api_delete():
    rel_path = request.json.get("path","")                                # Get relative file or folder path
    abs_path = safe_join(UPLOAD_ROOT, rel_path)
    try:
        if os.path.isfile(abs_path):
            os.remove(abs_path)                                           # Delete file
        elif os.path.isdir(abs_path):
            shutil.rmtree(abs_path)                                       # Delete folder recursively
        else:
            return jsonify({"code":1,"msg":"Not found"})
    except Exception as e:
        return jsonify({"code":1,"msg":"Delete failed:"+str(e)})
    return jsonify({'code':0})                                            # Return success

@app.route('/api/mkdir', methods=['POST'])
def api_mkdir():
    rel_dir = request.form.get("path","")                                 # Parent folder
    folder_name = request.form.get("name")
    if '/' in folder_name or '\\' in folder_name or not folder_name:
        return jsonify({"code":1, "msg":"Invalid folder name"})
    abs_dir = safe_join(UPLOAD_ROOT, rel_dir, folder_name)
    try:
        os.makedirs(abs_dir)                                              # Create new folder
    except Exception as e:
        return jsonify({"code":1, "msg":"Create failed:"+str(e)})
    return jsonify({'code':0})

@app.route('/api/move', methods=['POST'])
def api_move():
    src_rel = request.json.get("src","")                                  # Source path
    dst_rel = request.json.get("dst","")                                  # Destination folder path
    src_abs = safe_join(UPLOAD_ROOT, src_rel)
    dst_abs = safe_join(UPLOAD_ROOT, dst_rel)
    item_name = os.path.basename(src_abs)
    if os.path.abspath(src_abs) == os.path.abspath(dst_abs):
        return jsonify({'code':1,'msg':'Source and destination are the same'})
    if os.path.isdir(src_abs) and os.path.abspath(dst_abs).startswith(os.path.abspath(src_abs)+os.sep):
        return jsonify({'code':1,'msg':'Cannot move into its own subfolder'})
    try:
        if os.path.isfile(src_abs) or os.path.isdir(src_abs):
            if os.path.dirname(src_rel) == dst_rel:
                new_path = safe_join(UPLOAD_ROOT, dst_rel, request.json.get("new_name", item_name))
                shutil.move(src_abs, new_path)                            # Rename
            else:
                shutil.move(src_abs, os.path.join(dst_abs, item_name))    # Move to destination
        else:
            return jsonify({'code':1,'msg':'Not found'})
    except Exception as e:
        return jsonify({'code':1,'msg':'Move failed: '+str(e)})
    return jsonify({'code':0})

@app.route('/download')
def download():                                                           # Download file by path query
    rel_path = request.args.get('path','')
    abs_path = safe_join(UPLOAD_ROOT, rel_path)
    if not os.path.isfile(abs_path):
        abort(404)
    dir_name, file_name = os.path.split(abs_path)
    return send_from_directory(dir_name, file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
