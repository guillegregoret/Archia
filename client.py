import requests
import sys
import gzip
import os
import time
import psutil
import hashlib
from tqdm import tqdm
from datetime import datetime
import getpass

SERVER_URL = "https://archia.gregoret.com.ar:7200"
UPLOAD_URL = f"{SERVER_URL}/upload"
CHECK_HASH_URL = f"{SERVER_URL}/check-hash"
ARCHIVE_DELETED_URL = f"{SERVER_URL}/archive-deleted"
SYNC_STATS_URL = f"{SERVER_URL}/sync-stats"
SNAPSHOT_URL = f"{SERVER_URL}/snapshot"
LIST_SNAPSHOTS_URL = f"{SERVER_URL}/list-snapshots"
GET_SNAPSHOT_FILES_URL = f"{SERVER_URL}/get-snapshot-files"
DOWNLOAD_FILE_URL = f"{SERVER_URL}/download-file"
LIST_FILES_URL = f"{SERVER_URL}/list-files"
REGISTER_URL = f"{SERVER_URL}/register"
DELETE_SNAPSHOT_URL = f"{SERVER_URL}/delete-snapshot"
CHUNK_SIZE = 1024 * 1024  # 1MB per chunk
MAX_CPU_PERCENT = 85  # Maximum CPU usage percentage
MAX_MEMORY_PERCENT = 94  # Maximum memory usage percentage
THROTTLE_SLEEP = 0.1  # Sleep time in seconds when throttling

def check_resources():
    """Check if system resources are over threshold"""
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    return cpu_percent > MAX_CPU_PERCENT or memory_percent > MAX_MEMORY_PERCENT

def throttled_write(input_handle, output_handle, chunk_size, pbar=None):
    """Write data with resource throttling"""
    while True:
        # Check resource usage and wait if necessary
        while check_resources():
            time.sleep(THROTTLE_SLEEP)

        # Read and write chunk
        chunk = input_handle.read(chunk_size)
        if not chunk:
            break

        output_handle.write(chunk)
        if pbar:
            pbar.update(len(chunk))

        # Small sleep to prevent resource spikes
        time.sleep(0.001)

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_exists(file_hash, session):
    """Check if a file with the given hash exists on the server"""
    response = session.post(CHECK_HASH_URL, json={"hash": file_hash}, verify=True)
    return response.json().get("exists", False)

def upload_file(file_path, relative_path, session):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Calculate SHA-256 hash of the file
        file_hash = calculate_sha256(file_path)

        # Check if the file already exists on the server
        if check_file_exists(file_hash, session):
            print(f"File {file_path} already exists on the server. Skipping upload.")
            return

        # Create a temporary compressed file
        temp_compressed = os.path.join(os.path.dirname(file_path),
                                     f".temp_{os.path.basename(file_path)}.gz")

        # Get original file size for progress bar
        file_size = os.path.getsize(file_path)

        try:
            # First progress bar for compression
            print("Compressing file...")
            print(f"Current CPU usage: {psutil.cpu_percent()}%")
            print(f"Current memory usage: {psutil.virtual_memory().percent}%")

            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Compressing") as pbar:
                with open(file_path, 'rb') as f_in:
                    with gzip.open(temp_compressed, 'wb', compresslevel=1) as f_out:
                        throttled_write(f_in, f_out, CHUNK_SIZE, pbar)

            # Get compressed file size for upload progress bar
            compressed_size = os.path.getsize(temp_compressed)

            # Second progress bar for upload
            print("\nUploading file...")
            print(f"Current CPU usage: {psutil.cpu_percent()}%")
            print(f"Current memory usage: {psutil.virtual_memory().percent}%")

            with tqdm(total=compressed_size, unit='B', unit_scale=True, desc="Uploading") as pbar:
                with open(temp_compressed, 'rb') as f:
                    # Start time
                    start_time = time.time()

                    # Prepare the file for upload
                    files = {
                        'file': (
                            os.path.basename(file_path) + '.gz',
                            f,
                            'application/gzip'
                        )
                    }
                    data = {'path': relative_path}

                    # Custom upload with throttling using requests
                    response = session.post(
                        UPLOAD_URL,
                        files=files,
                        data=data,
                        verify=True
                    )

                    # Update progress bar to completion
                    pbar.update(compressed_size)

            # Calculate and display statistics
            end_time = time.time()
            elapsed_time = end_time - start_time
            speed = file_size / elapsed_time / 1024  # Speed in KB/s

            print(f"\nUpload completed in {elapsed_time:.2f} seconds.")
            print(f"Transfer speed: {speed:.2f} KB/s")
            print(f"Original size: {file_size/1024/1024:.2f} MB")
            print(f"Compressed size: {compressed_size/1024/1024:.2f} MB")
            print(f"Compression ratio: {(compressed_size/file_size)*100:.1f}%")
            print(f"Final CPU usage: {psutil.cpu_percent()}%")
            print(f"Final memory usage: {psutil.virtual_memory().percent}%")
            print(response.json())

        finally:
            # Clean up temporary file
            if os.path.exists(temp_compressed):
                os.remove(temp_compressed)

    except Exception as e:
        print(f"Error: {e}")

def upload_folder(folder_path, session):
    """Upload all files in the folder."""
    added_files = []
    modified_files = []
    unmodified_files = []
    removed_files = []
    origin_size = 0
    compressed_size = 0

    # Get list of existing files on the server
    response = session.get(LIST_FILES_URL, verify=True)
    print(f"Response status code: {response.status_code}")
    print(f"Response content: {response.content}")
    if response.status_code == 200:
        existing_files = {os.path.normpath(file["path"]) for file in response.json()}
    else:
        print("Failed to list files on the server.")
        return

    # Get list of files on the client
    client_files = set()
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(file_path, start=folder_path)
            client_files.add(os.path.normpath(relative_path))
            origin_size += os.path.getsize(file_path)

    # Determine added, modified, and unmodified files
    for file_path in client_files:
        if file_path not in existing_files:
            added_files.append(file_path)
        else:
            modified_files.append(file_path)

    # Determine removed files
    removed_files = existing_files - client_files

    # Upload files
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(file_path, start=folder_path)
            print(f"\nProcessing file: {file_path}")
            upload_file(file_path, relative_path, session)
            compressed_size += os.path.getsize(file_path)

    # Archive deleted files on the server
    if removed_files:
        response = session.post(ARCHIVE_DELETED_URL, json={"deleted_files": list(removed_files)}, verify=True)
        print(response.json())

    # Send sync statistics to the server
    response = session.post(SYNC_STATS_URL, json={
        "origin_size": origin_size,
        "compressed_size": compressed_size,
        "added_files": added_files,
        "modified_files": modified_files,
        "unmodified_files": unmodified_files,
        "removed_files": list(removed_files)
    }, verify=True)
    print(response.json())

    # Create a snapshot on the server
    response = session.post(SNAPSHOT_URL, verify=True)
    print(response.json())

def list_snapshots(session):
    response = session.get(LIST_SNAPSHOTS_URL, verify=True)
    if response.status_code == 200:
        snapshots = response.json()
        for snapshot in snapshots:
            print(f"Snapshot Name: {snapshot['name']}")
            print(f"Number of Files: {snapshot['number_of_files']}")
            print(f"Size: {snapshot['size']} bytes")
    else:
        print("Failed to list snapshots.")

def restore_snapshot(snapshot_name, restore_path, session):
    response = session.post(GET_SNAPSHOT_FILES_URL, json={"snapshot_name": snapshot_name}, verify=True)
    if response.status_code == 200:
        snapshot_files = response.json()
        os.makedirs(restore_path, exist_ok=True)
        for file in snapshot_files:
            download_url = f"{DOWNLOAD_FILE_URL}/{file}"
            response = session.get(download_url, stream=True, verify=True)
            if response.status_code == 200:
                dest_path = os.path.join(restore_path, file)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                        f.write(chunk)
                print(f"Downloaded {file} to {dest_path}")
            else:
                print(f"Failed to download {file}")
        print(f"Snapshot {snapshot_name} restored successfully.")
    else:
        print("Failed to restore snapshot.")

def register_user(session):
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    response = session.post(REGISTER_URL, json={"username": username, "password": password}, verify=True)
    if response.status_code == 201:
        print("User registered successfully.")
    else:
        print("Failed to register user.")

def delete_snapshot(snapshot_name, session):
    response = session.post(DELETE_SNAPSHOT_URL, json={"snapshot_name": snapshot_name}, verify=True)
    if response.status_code == 200:
        print(f"Snapshot {snapshot_name} deleted successfully.")
    else:
        print("Failed to delete snapshot.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backup_client.py <file_path or folder_path> [restore <snapshot_name> <restore_path>]")
    else:
        # Set process priority to below normal
        try:
            import win32api
            import win32process
            import win32con
            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
            win32process.SetPriorityClass(handle, win32process.BELOW_NORMAL_PRIORITY_CLASS)
        except ImportError:
            # If on non-Windows system, try to use nice
            try:
                os.nice(10)  # Increase niceness (lower priority)
            except:
                pass

        # Create a session with basic auth
        session = requests.Session()
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        session.auth = (username, password)

        if sys.argv[1] == "restore":
            if len(sys.argv) < 4:
                print("Usage: python backup_client.py restore <snapshot_name> <restore_path>")
            else:
                snapshot_name = sys.argv[2]
                restore_path = sys.argv[3]
                restore_snapshot(snapshot_name, restore_path, session)
        elif sys.argv[1] == "list-snapshots":
            list_snapshots(session)
        elif sys.argv[1] == "register":
            register_user(session)
        elif sys.argv[1] == "delete-snapshot":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py delete-snapshot <snapshot_name>")
            else:
                snapshot_name = sys.argv[2]
                delete_snapshot(snapshot_name, session)
        else:
            file_or_folder_path = sys.argv[1]
            if os.path.isdir(file_or_folder_path):
                upload_folder(file_or_folder_path, session)
            else:
                upload_file(file_or_folder_path, os.path.basename(file_or_folder_path), session)
