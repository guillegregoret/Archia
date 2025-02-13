from flask import Flask, request, jsonify, send_file
import os
import gzip
import shutil
import hashlib
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import getpass

app = Flask(__name__)
UPLOAD_FOLDER = "./backups"
ARCHIVE_FOLDER = "./archives"
SNAPSHOT_FOLDER = "./snapshots"
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
HASHES_FILE = os.path.join(UPLOAD_FOLDER, "hashes.json")
SNAPSHOTS_FILE = os.path.join(UPLOAD_FOLDER, "snapshots.json")
USERS_FILE = os.path.join(UPLOAD_FOLDER, "users.json")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ARCHIVE_FOLDER, exist_ok=True)
os.makedirs(SNAPSHOT_FOLDER, exist_ok=True)

# Load existing hashes
if os.path.exists(HASHES_FILE):
    with open(HASHES_FILE, 'r') as f:
        file_hashes = json.load(f)
else:
    file_hashes = {}

# Load existing snapshots
if os.path.exists(SNAPSHOTS_FILE):
    with open(SNAPSHOTS_FILE, 'r') as f:
        snapshots = json.load(f)
else:
    snapshots = {}

# Load existing users
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
else:
    users = {}

def save_hashes():
    with open(HASHES_FILE, 'w') as f:
        json.dump(file_hashes, f)

def save_snapshots():
    with open(SNAPSHOTS_FILE, 'w') as f:
        json.dump(snapshots, f)

def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def check_auth(username, password):
    if username in users and check_password_hash(users[username]['password'], password):
        return True
    return False

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    users[username] = {"password": generate_password_hash(password)}
    save_users()
    return jsonify({"message": "User registered successfully"}), 201

@app.route("/upload", methods=["POST"])
@requires_auth
def upload_file():
    if "file" not in request.files or "path" not in request.form:
        return jsonify({"error": "No file part or path"}), 400

    file = request.files["file"]
    relative_path = request.form["path"]  # Path from client (e.g., "docs\file.txt" from Windows)
    username = request.authorization.username

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        # **Fix Windows backslashes to Linux slashes**
        safe_relative_path = relative_path.replace("\\", "/")  # Convert Windows path to Linux format
        safe_relative_path = os.path.normpath(safe_relative_path)  # Normalize path

        user_folder = os.path.join(UPLOAD_FOLDER, username)
        final_path = os.path.join(user_folder, safe_relative_path)  # Correct file destination
        final_dir = os.path.dirname(final_path)  # Extract directory path

        os.makedirs(final_dir, exist_ok=True)  # **Ensure correct folder structure**

        # Save the compressed file temporarily
        temp_gz_path = final_path + ".gz"

        file.save(temp_gz_path)

        # Calculate SHA-256 hash of the decompressed file
        sha256_hash = hashlib.sha256()
        with gzip.open(temp_gz_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        print(f"File hash calculated: {file_hash}")

        # Check if the file already exists
        existing_file_hash = file_hashes.get(final_path)
        print(f"Existing file hash: {existing_file_hash}")

        # **Only archive if the file is actually different**
        if existing_file_hash and existing_file_hash != file_hash:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            archive_path = os.path.join(ARCHIVE_FOLDER, username, safe_relative_path + f".archive.{timestamp}")
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)

            # **Archive the old file BEFORE writing the new one**
            shutil.move(final_path, archive_path)
            print(f"Archived old file to {archive_path}")

        # **Now, save the new file in the original location**
        with gzip.open(temp_gz_path, 'rb') as f_in:
            with open(final_path, 'wb') as f_out:
                print("-->>> Saving new file in the original location")
                shutil.copyfileobj(f_in, f_out, length=CHUNK_SIZE)

        # Save the new file hash
        file_hashes[final_path] = file_hash
        save_hashes()

        # Remove the temporary compressed file after successful processing
        os.remove(temp_gz_path)

        return jsonify({
            "message": "File uploaded and decompressed successfully",
            "filename": file.filename,
            "final_path": final_path,
            "hash": file_hash
        }), 200

    except Exception as e:
        if os.path.exists(temp_gz_path):
            os.remove(temp_gz_path)
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500


@app.route("/check-hash", methods=["POST"])
@requires_auth
def check_hash():
    data = request.json
    file_hash = data.get("hash")
    if file_hash in file_hashes.values():
        return jsonify({"exists": True}), 200
    else:
        return jsonify({"exists": False}), 200

@app.route("/list-files", methods=["GET"])
@requires_auth
def list_files():
    try:
        username = request.authorization.username
        user_folder = os.path.join(UPLOAD_FOLDER, username)
        files = []
        for root, _, filenames in os.walk(user_folder):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path) and filename not in ["hashes.json", "snapshots.json", "users.json"]:
                    file_size = os.path.getsize(file_path)
                    file_size_kb = file_size / 1024  # Convert bytes to kilobytes
                    relative_path = os.path.relpath(file_path, user_folder)
                    files.append({
                        "filename": filename,
                        "size_kb": file_size_kb,
                        "path": relative_path
                    })
        return jsonify(files), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list files: {str(e)}"}), 500

@app.route("/archive-deleted", methods=["POST"])
@requires_auth
def archive_deleted():
    data = request.json
    deleted_files = data.get("deleted_files", [])
    username = request.authorization.username
    for file_path in deleted_files:
        safe_relative_path = file_path.replace("\\", "/")  # Convert Windows path to Linux format
        safe_relative_path = os.path.normpath(safe_relative_path)  # Normalize path
        final_path = os.path.join(UPLOAD_FOLDER, username, safe_relative_path)
        if os.path.exists(final_path):
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            archive_path = os.path.join(ARCHIVE_FOLDER, username, safe_relative_path + f".archive.{timestamp}")
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            shutil.move(final_path, archive_path)
            print(f"Archived deleted file to {archive_path}")
    return jsonify({"message": "Deleted files archived successfully"}), 200

@app.route("/sync-stats", methods=["POST"])
@requires_auth
def sync_stats():
    data = request.json
    origin_size = data.get("origin_size", 0)
    compressed_size = data.get("compressed_size", 0)
    added_files = data.get("added_files", [])
    modified_files = data.get("modified_files", [])
    unmodified_files = data.get("unmodified_files", [])
    removed_files = data.get("removed_files", [])

    # Calculate remote size and file counts
    username = request.authorization.username
    user_folder = os.path.join(UPLOAD_FOLDER, username)
    remote_size = 0
    remote_files = []
    for root, _, filenames in os.walk(user_folder):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path) and filename not in ["hashes.json", "snapshots.json", "users.json"]:
                file_size = os.path.getsize(file_path)
                remote_size += file_size
                relative_path = os.path.relpath(file_path, user_folder)
                remote_files.append(relative_path)

    # Calculate statistics
    stats = {
        "origin_size": origin_size,
        "compressed_size": compressed_size,
        "remote_size": remote_size,
        "files_before_sync": len(remote_files) - len(added_files) - len(modified_files) + len(removed_files),
        "files_after_sync": len(remote_files),
        "added_files": len(added_files),
        "modified_files": len(modified_files),
        "unmodified_files": len(unmodified_files),
        "removed_files": len(removed_files)
    }

    return jsonify(stats), 200

@app.route("/snapshot", methods=["POST"])
@requires_auth
def snapshot():
    username = request.authorization.username
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    snapshot_files = []
    user_folder = os.path.join(UPLOAD_FOLDER, username)
    for root, _, filenames in os.walk(user_folder):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path) and filename not in ["hashes.json", "snapshots.json", "users.json"]:
                relative_path = os.path.relpath(file_path, user_folder)
                snapshot_files.append(relative_path)

    if username not in snapshots:
        snapshots[username] = {}
    snapshots[username][timestamp] = snapshot_files
    save_snapshots()

    return jsonify({"message": "Snapshot created successfully", "timestamp": timestamp}), 200

@app.route("/list-snapshots", methods=["GET"])
@requires_auth
def list_snapshots():
    username = request.authorization.username
    snapshot_list = []
    if username in snapshots:
        for timestamp, files in snapshots[username].items():
            snapshot_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, username, file)) for file in files if os.path.exists(os.path.join(UPLOAD_FOLDER, username, file)))
            snapshot_list.append({
                "name": timestamp,
                "number_of_files": len(files),
                "size": snapshot_size
            })
    return jsonify(snapshot_list), 200

@app.route("/get-snapshot-files", methods=["POST"])
@requires_auth
def get_snapshot_files():
    data = request.json
    snapshot_name = data.get("snapshot_name")
    username = request.authorization.username

    if username in snapshots and snapshot_name in snapshots[username]:
        snapshot_files = snapshots[username][snapshot_name]
        return jsonify(snapshot_files), 200
    else:
        return jsonify({"error": "Snapshot not found"}), 404

@app.route("/download-file/<path:filename>", methods=["GET"])
@requires_auth
def download_file(filename):
    username = request.authorization.username
    try:
        return send_file(os.path.join(UPLOAD_FOLDER, username, filename), as_attachment=True)
    except Exception as e:
        return jsonify({"error": f"Failed to download file: {str(e)}"}), 500

@app.route("/delete-snapshot", methods=["POST"])
@requires_auth
def delete_snapshot():
    data = request.json
    snapshot_name = data.get("snapshot_name")
    username = request.authorization.username

    if username in snapshots and snapshot_name in snapshots[username]:
        del snapshots[username][snapshot_name]
        save_snapshots()
        return jsonify({"message": f"Snapshot {snapshot_name} deleted successfully"}), 200
    else:
        return jsonify({"error": "Snapshot not found"}), 404

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=7200,
        ssl_context=(
            "/etc/letsencrypt/live/archia.gregoret.com.ar/fullchain.pem",
            "/etc/letsencrypt/live/archia.gregoret.com.ar/privkey.pem"
        )
    )
