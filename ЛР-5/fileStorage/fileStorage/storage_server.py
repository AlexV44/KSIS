import os
import shutil
import json
from datetime import datetime, timezone
from flask import Flask, request, Response, abort, send_file

app = Flask(__name__)

# Корневая директория хранилища
STORAGE_ROOT = os.environ.get('STORAGE_ROOT', './storage')
os.makedirs(STORAGE_ROOT, exist_ok=True)

def safe_path(request_path):
    """
    Преобразует относительный путь из URL в абсолютный путь внутри STORAGE_ROOT.
    Защита от path traversal.
    """
    if request_path.startswith('/'):
        request_path = request_path[1:]
    parts = request_path.split('/')
    safe_parts = []
    for part in parts:
        if part in ('', '.', '..'):
            continue
        safe_parts.append(part)
    safe_path = os.path.join(STORAGE_ROOT, *safe_parts)
    safe_path = os.path.abspath(safe_path)
    if not safe_path.startswith(os.path.abspath(STORAGE_ROOT)):
        abort(403, "Access denied")
    return safe_path

def get_file_metadata(file_path):
    """Возвращает размер и дату последнего изменения файла."""
    stat = os.stat(file_path)
    size = stat.st_size
    last_modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    return size, last_modified

@app.route('/<path:filepath>', methods=['PUT'])
def put_file(filepath):
    target_path = safe_path(filepath)

    parent_dir = os.path.dirname(target_path)
    if os.path.exists(parent_dir) and not os.path.isdir(parent_dir):
        abort(409, "Parent path is a file, cannot create directory")

    if request.content_length == 0 and not request.get_data():
        abort(400, "No file data provided")

    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    existed = os.path.exists(target_path)
    with open(target_path, 'wb') as f:
        while True:
            chunk = request.stream.read(8192)
            if not chunk:
                break
            f.write(chunk)

    status_code = 200 if existed else 201
    return Response(status=status_code)

@app.route('/<path:filepath>', methods=['GET'])
def get_file_or_directory(filepath):
    target_path = safe_path(filepath)

    if not os.path.exists(target_path):
        abort(404, "File or directory not found")

    if os.path.isdir(target_path):
        items = []
        for name in os.listdir(target_path):
            item_path = os.path.join(target_path, name)
            items.append({
                "name": name,
                "type": "directory" if os.path.isdir(item_path) else "file"
            })
        return Response(
            response=json.dumps(items, indent=2),
            status=200,
            mimetype='application/json'
        )

    return send_file(target_path, as_attachment=False, conditional=True)

@app.route('/<path:filepath>', methods=['HEAD'])
def head_file(filepath):
    target_path = safe_path(filepath)

    if not os.path.exists(target_path) or os.path.isdir(target_path):
        abort(404, "File not found")

    size, last_modified = get_file_metadata(target_path)
    resp = Response(status=200)
    resp.headers['Content-Length'] = size
    resp.headers['Last-Modified'] = last_modified
    return resp

@app.route('/<path:filepath>', methods=['DELETE'])
def delete_file_or_directory(filepath):
    target_path = safe_path(filepath)

    if not os.path.exists(target_path):
        abort(404, "File or directory not found")

    if os.path.isdir(target_path):
        shutil.rmtree(target_path)
    else:
        os.remove(target_path)

    return Response(status=204)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)