# Archia

Archia is a backup and snapshot management system that allows users to upload files, create snapshots, and restore files from snapshots. It ensures that files are securely backed up and can be restored to their original state.

## Features

* **User Authentication**: Users can register and authenticate to use the system.
* **File Upload**: Users can upload files to the server, which are then backed up.
* **Snapshot Management**: Users can create snapshots of their files, list snapshots, restore snapshots, and delete snapshots.
* **File Deduplication**: Files are stored by their SHA-256 hash to avoid duplicates.
* **Delta Storage**: Only changes to files are stored, saving space.
* **Secure API**: The system uses HTTPS and basic authentication to ensure secure communication.

## Prerequisites

* Python 3.x
* Flask
* Requests
* psutil
* tqdm
* hashlib
* gzip
* shutil
* json
* datetime
* getpass
* werkzeug

## Installation

1. Clone the repository:

```bash
git clone <repository_url>
cd Archia
```

2. Install the required packages:

```bash
pip install -r requirements.txt
```

3. Run the server:

```bash
python server.py
```

4. Run the client:

```bash
python client.py <file_path_or_folder_path> [restore <snapshot_name> <restore_path>]
```

## Usage

### Register a User

```bash
python client.py register
```

### Upload Files

```bash
python client.py <file_path_or_folder_path>
```

### List Snapshots

```bash
python client.py list-snapshots
```

### Restore a Snapshot

```bash
python client.py restore <snapshot_name> <restore_path>
```

### Delete a Snapshot

```bash
python client.py delete-snapshot <snapshot_name>
```

## Diagrams

### Client-Server Communication

### Architecture

## Explanation of Diagrams

### Client-Server Communication
* The client communicates with the server using HTTPS requests.
* The client can register a user, upload files, list snapshots, restore snapshots, and delete snapshots.
* The server responds with the appropriate data or status messages.

### Architecture
* The system consists of a client and a server.
* The client is responsible for uploading files, creating snapshots, and restoring snapshots.
* The server is responsible for storing files, managing snapshots, and handling client requests.
