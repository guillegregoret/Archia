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
import shutil
import json
import tempfile
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import boto3
import threading

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
PACKAGE_URL = f"{SERVER_URL}/package"
CHUNK_SIZE = 1024 * 1024  # 1MB per chunk
MAX_CPU_PERCENT = 85  # Maximum CPU usage percentage
MAX_MEMORY_PERCENT = 94  # Maximum memory usage percentage
THROTTLE_SLEEP = 0.1  # Sleep time in seconds when throttling
CONFIG_FILE = "config.json"

# Transfer animation frames
computer = "💻"
cloud = "☁️"
file_emoji = "📄"
folder_emoji = "📁"
frames = [
    f"{computer}{file_emoji}          {cloud}",
    f"{computer} {file_emoji}         {cloud}",
    f"{computer}  {file_emoji}        {cloud}",
    f"{computer}   {file_emoji}       {cloud}",
    f"{computer}    {file_emoji}      {cloud}",
    f"{computer}     {file_emoji}     {cloud}",
    f"{computer}      {file_emoji}    {cloud}",
    f"{computer}       {file_emoji}   {cloud}",
    f"{computer}        {file_emoji}  {cloud}",
    f"{computer}         {file_emoji} {cloud}",
    f"{computer}          {file_emoji}{cloud}",
    f"{computer}{folder_emoji}          {cloud}",
    f"{computer} {folder_emoji}         {cloud}",
    f"{computer}  {folder_emoji}        {cloud}",
    f"{computer}   {folder_emoji}       {cloud}",
    f"{computer}    {folder_emoji}      {cloud}",
    f"{computer}     {folder_emoji}     {cloud}",
    f"{computer}      {folder_emoji}    {cloud}",
    f"{computer}       {folder_emoji}   {cloud}",
    f"{computer}        {folder_emoji}  {cloud}",
    f"{computer}         {folder_emoji} {cloud}",
    f"{computer}          {folder_emoji}{cloud}",
]

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

def add_host(session):
    username = input("Enter username: ")
    hostname = input("Enter hostname: ")
    response = session.post(f"{SERVER_URL}/add-host", json={"username": username, "hostname": hostname}, verify=True)
    if response.status_code == 201:
        print("Host added successfully.")
    else:
        print("Failed to add host.")

def delete_snapshot(snapshot_name, session):
    response = session.post(DELETE_SNAPSHOT_URL, json={"snapshot_name": snapshot_name}, verify=True)
    if response.status_code == 200:
        print(f"Snapshot {snapshot_name} deleted successfully.")
    else:
        print("Failed to delete snapshot.")

def package_folder(folder_path, session):
    """Package a folder and upload it to the server."""
    with tempfile.TemporaryDirectory() as temp_dir:
        package_path = os.path.join(temp_dir, "package.gz")
        with gzip.open(package_path, 'wb') as f_out:
            for root, _, files in os.walk(folder_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)

        # Upload the package to the server
        with open(package_path, 'rb') as f:
            files = {'file': (os.path.basename(package_path), f, 'application/gzip')}
            response = session.post(PACKAGE_URL, files=files, verify=True)
            if response.status_code == 200:
                print("Package uploaded successfully.")
            else:
                print(f"Failed to upload package: {response.json()}")

def upload_to_azure(folder_path, azure_storage_account, azure_storage_key):
    """Upload a folder to Azure Storage."""
    try:
        # Initialize the BlobServiceClient with the account name and key
        blob_service_client = BlobServiceClient(account_url=f"https://{azure_storage_account}.blob.core.windows.net", credential=azure_storage_key)

        # Create a container if it doesn't exist
        container_name = "archia-backups"
        container_client = blob_service_client.get_container_client(container_name)
        container_client.create_container()

        # Upload files to the container
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)
                with open(file_path, "rb") as data:
                    blob_client.upload_blob(data)
                print(f"Uploaded {file_name} to Azure Storage.")

    except Exception as e:
        print(f"Failed to upload to Azure Storage: {str(e)}")

def upload_to_s3(folder_path, aws_access_key, aws_secret_key, aws_region, aws_bucket):
    """Upload a folder to AWS S3."""
    try:
        # Initialize the S3 client
        s3_client = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)

        # Upload files to the S3 bucket
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                s3_client.upload_file(file_path, aws_bucket, file_name)
                print(f"Uploaded {file_name} to AWS S3.")

    except NoCredentialsError:
        print("Credentials not available.")
    except PartialCredentialsError:
        print("Incomplete credentials provided.")
    except Exception as e:
        print(f"Failed to upload to AWS S3: {str(e)}")

def upload_compressed_package_to_azure(folder_path, azure_storage_account, azure_storage_key):
    """Upload a compressed package to Azure Storage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        package_path = os.path.join(temp_dir, "package.gz")
        with gzip.open(package_path, 'wb') as f_out:
            for root, _, files in os.walk(folder_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)

        # Upload the package to Azure Storage
        blob_service_client = BlobServiceClient(account_url=f"https://{azure_storage_account}.blob.core.windows.net", credential=azure_storage_key)
        container_name = "archia-backup-"+datetime.now().strftime('%Y%m%d%H%M%S')
        container_client = blob_service_client.get_container_client(container_name)
        container_client.create_container()
        blob_client = blob_service_client.get_blob_client(container=container_name, blob="package.gz")
        with open(package_path, "rb") as data:
            blob_client.upload_blob(data)
        print(f"Uploaded compressed package to Azure Storage.")

def upload_compressed_package_to_s3(folder_path, aws_access_key, aws_secret_key, aws_region, aws_bucket):
    """Upload a compressed package to AWS S3."""
    with tempfile.TemporaryDirectory() as temp_dir:
        package_path = os.path.join(temp_dir, "package.gz")
        with gzip.open(package_path, 'wb') as f_out:
            for root, _, files in os.walk(folder_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)

        # Upload the package to AWS S3
        s3_client = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        s3_client.upload_file(package_path, aws_bucket, "package.gz")
        print(f"Uploaded compressed package to AWS S3.")

def load_config():
    """Load the configuration from config.json"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    else:
        return {}

def save_config(config):
    """Save the configuration to config.json"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def transfer_animation(stop_event):
    """Transfer animation."""
    frame_index = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{frames[frame_index % len(frames)]}")
        sys.stdout.flush()
        frame_index += 1
        time.sleep(0.08)

def get_azure_credentials():
    """Wizard to get Azure credentials."""
    azure_storage_account = input("Enter Azure Storage Account Name: ")
    azure_storage_key = getpass.getpass("Enter Azure Storage Account Key: ")
    return azure_storage_account, azure_storage_key

def get_aws_credentials():
    """Wizard to get AWS credentials."""
    aws_access_key = input("Enter AWS Access Key: ")
    aws_secret_key = getpass.getpass("Enter AWS Secret Key: ")
    aws_region = input("Enter AWS Region: ")
    aws_bucket = input("Enter AWS S3 Bucket Name: ")
    return aws_access_key, aws_secret_key, aws_region, aws_bucket

def show_help():
    """Display help information."""
    help_text = """
    Archia Backup Client Help

    Commands:

    1. Register a User:
       python client.py register

    2. Add a Host:
       python client.py add-host

    3. Upload a File or Folder:
       python client.py <file_path_or_folder_path>

    4. List Snapshots:
       python client.py list-snapshots

    5. Restore a Snapshot:
       python client.py restore <snapshot_name> <restore_path>

    6. Delete a Snapshot:
       python client.py delete-snapshot <snapshot_name>

    7. Package a Folder:
       python client.py package <folder_path>

    8. Upload to Azure Storage:
       python client.py azure <folder_path>

    9. Upload to AWS S3:
       python client.py s3 <folder_path>

    10. Upload Compressed Package to Azure Storage:
        python client.py azure-compressed <folder_path>

    11. Upload Compressed Package to AWS S3:
        python client.py s3-compressed <folder_path>

    Examples:

    - Register a user:
      python client.py register

    - Add a host:
      python client.py add-host

    - Upload a folder:
      python client.py /path/to/folder

    - List snapshots:
      python client.py list-snapshots

    - Restore a snapshot:
      python client.py restore snapshot1 /path/to/restore

    - Delete a snapshot:
      python client.py delete-snapshot snapshot1

    - Package a folder:
      python client.py package /path/to/folder

    - Upload to Azure Storage:
      python client.py azure /path/to/folder

    - Upload to AWS S3:
      python client.py s3 /path/to/folder

    - Upload compressed package to Azure Storage:
      python client.py azure-compressed /path/to/folder

    - Upload compressed package to AWS S3:
      python client.py s3-compressed /path/to/folder
    """
    print(help_text)

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

        # Load configuration
        config = load_config()

        if sys.argv[1] == "help":
            show_help()
        elif sys.argv[1] == "restore":
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
        elif sys.argv[1] == "add-host":
            add_host(session)
        elif sys.argv[1] == "delete-snapshot":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py delete-snapshot <snapshot_name>")
            else:
                snapshot_name = sys.argv[2]
                delete_snapshot(snapshot_name, session)
        elif sys.argv[1] == "package":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py package <folder_path>")
            else:
                folder_path = sys.argv[2]
                package_folder(folder_path, session)
        elif sys.argv[1] == "azure":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py azure <folder_path>")
            else:
                folder_path = sys.argv[2]
                azure_storage_account, azure_storage_key = get_azure_credentials()
                stop_event = threading.Event()
                transfer_thread = threading.Thread(target=transfer_animation, args=(stop_event,))
                transfer_thread.start()
                upload_to_azure(folder_path, azure_storage_account, azure_storage_key)
                stop_event.set()
                transfer_thread.join()
        elif sys.argv[1] == "s3":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py s3 <folder_path>")
            else:
                folder_path = sys.argv[2]
                aws_access_key, aws_secret_key, aws_region, aws_bucket = get_aws_credentials()
                stop_event = threading.Event()
                transfer_thread = threading.Thread(target=transfer_animation, args=(stop_event,))
                transfer_thread.start()
                upload_to_s3(folder_path, aws_access_key, aws_secret_key, aws_region, aws_bucket)
                stop_event.set()
                transfer_thread.join()
        elif sys.argv[1] == "azure-compressed":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py azure-compressed <folder_path>")
            else:
                folder_path = sys.argv[2]
                azure_storage_account, azure_storage_key = get_azure_credentials()
                stop_event = threading.Event()
                transfer_thread = threading.Thread(target=transfer_animation, args=(stop_event,))
                transfer_thread.start()
                upload_compressed_package_to_azure(folder_path, azure_storage_account, azure_storage_key)
                stop_event.set()
                transfer_thread.join()
        elif sys.argv[1] == "s3-compressed":
            if len(sys.argv) < 3:
                print("Usage: python backup_client.py s3-compressed <folder_path>")
            else:
                folder_path = sys.argv[2]
                aws_access_key, aws_secret_key, aws_region, aws_bucket = get_aws_credentials()
                stop_event = threading.Event()
                transfer_thread = threading.Thread(target=transfer_animation, args=(stop_event,))
                transfer_thread.start()
                upload_compressed_package_to_s3(folder_path, aws_access_key, aws_secret_key, aws_region, aws_bucket)
                stop_event.set()
                transfer_thread.join()
        else:
            file_or_folder_path = sys.argv[1]
            if os.path.isdir(file_or_folder_path):
                upload_folder(file_or_folder_path, session)
            else:
                upload_file(file_or_folder_path, os.path.basename(file_or_folder_path), session)

            # Save the current host configuration
            config[username] = {"hosts": config.get(username, {}).get("hosts", []) + [file_or_folder_path]}
            save_config(config)
