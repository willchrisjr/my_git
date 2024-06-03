import sys
import os
import zlib
import hashlib
import time

def main():
    command = sys.argv[1]
    if command == "init":
        initialize_repository()
    elif command == "cat-file" and sys.argv[2] == "-p":
        blob_sha = sys.argv[3]
        read_blob(blob_sha)
    elif command == "hash-object" and sys.argv[2] == "-w":
        file_path = sys.argv[3]
        print(hash_object(file_path))  # Ensure the SHA-1 hash is printed
    elif command == "ls-tree" and sys.argv[2] == "--name-only":
        tree_sha = sys.argv[3]
        ls_tree(tree_sha)
    elif command == "write-tree":
        print(write_tree("."))  # Ensure the SHA-1 hash is printed
    elif command == "commit-tree":
        tree_sha = sys.argv[2]
        parent_commit_sha = sys.argv[4]
        message = sys.argv[6]
        print(commit_tree(tree_sha, parent_commit_sha, message))  # Ensure the SHA-1 hash is printed
    else:
        raise RuntimeError(f"Unknown command #{command}")

def initialize_repository():
    """Initializes a new git repository."""
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    print("Initialized git directory")

def read_blob(blob_sha):
    """Reads a blob object and prints its content."""
    dir_name = blob_sha[:2]
    file_name = blob_sha[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    with open(object_path, "rb") as f:
        compressed_data = f.read()
        decompressed_data = zlib.decompress(compressed_data)
    
    null_byte_index = decompressed_data.index(b'\x00')
    content = decompressed_data[null_byte_index + 1:]
    
    sys.stdout.buffer.write(content)

def hash_object(file_path):
    """Computes the SHA-1 hash of a file and writes the blob object to the repository."""
    with open(file_path, "rb") as f:
        content = f.read()
    
    size = len(content)
    header = f"blob {size}\0".encode()
    store = header + content
    
    sha1 = hashlib.sha1(store).hexdigest()
    
    dir_name = sha1[:2]
    file_name = sha1[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    if not os.path.exists(os.path.join(".git", "objects", dir_name)):
        os.mkdir(os.path.join(".git", "objects", dir_name))
    
    compressed_data = zlib.compress(store)
    
    with open(object_path, "wb") as f:
        f.write(compressed_data)
    
    return sha1  # Ensure the SHA-1 hash is returned

def ls_tree(tree_sha):
    """Inspects a tree object and prints the names of the entries."""
    dir_name = tree_sha[:2]
    file_name = tree_sha[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    with open(object_path, "rb") as f:
        compressed_data = f.read()
        decompressed_data = zlib.decompress(compressed_data)
    
    null_byte_index = decompressed_data.index(b'\x00')
    entries_data = decompressed_data[null_byte_index + 1:]
    
    entries = []
    i = 0
    while i < len(entries_data):
        mode_end = entries_data.index(b' ', i)
        mode = entries_data[i:mode_end].decode()
        i = mode_end + 1
        
        name_end = entries_data.index(b'\x00', i)
        name = entries_data[i:name_end].decode()
        i = name_end + 1
        
        sha = entries_data[i:i + 20]
        i += 20
        
        entries.append((mode, name, sha))
    
    for entry in entries:
        print(entry[1])

def write_tree(path):
    """Creates a tree object from the current state of the working directory and writes it to the repository."""
    if os.path.isfile(path):
        return create_blob_entry(path)
    
    entries = []
    for entry in sorted(os.listdir(path)):
        if entry == ".git":
            continue
        
        entry_path = os.path.join(path, entry)
        if os.path.isdir(entry_path):
            mode = "40000"
            sha = write_tree(entry_path)
        else:
            mode = "100644"
            sha = create_blob_entry(entry_path)
        
        sha_bytes = bytes.fromhex(sha)
        entries.append(f"{mode} {entry}\0".encode() + sha_bytes)
    
    tree_content = b"".join(entries)
    header = f"tree {len(tree_content)}\0".encode()
    store = header + tree_content
    
    sha1 = hashlib.sha1(store).hexdigest()
    
    dir_name = sha1[:2]
    file_name = sha1[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    if not os.path.exists(os.path.join(".git", "objects", dir_name)):
        os.mkdir(os.path.join(".git", "objects", dir_name))
    
    compressed_data = zlib.compress(store)
    
    with open(object_path, "wb") as f:
        f.write(compressed_data)
    
    return sha1

def create_blob_entry(path):
    """Creates a blob object for a file and writes it to the repository."""
    with open(path, "rb") as f:
        data = f.read()
    
    header = f"blob {len(data)}\0".encode()
    store = header + data
    
    sha = hashlib.sha1(store).hexdigest()
    
    dir_name = sha[:2]
    file_name = sha[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    if not os.path.exists(os.path.join(".git", "objects", dir_name)):
        os.mkdir(os.path.join(".git", "objects", dir_name))
    
    compressed_data = zlib.compress(store)
    
    with open(object_path, "wb") as f:
        f.write(compressed_data)
    
    return sha

def commit_tree(tree_sha, parent_commit_sha, message):
    """Creates a commit object and writes it to the repository."""
    author = "Author Name <author@example.com>"
    committer = "Committer Name <committer@example.com>"
    timestamp = int(time.time())
    timezone = time.strftime("%z")
    
    commit_content = (
        f"tree {tree_sha}\n"
        f"parent {parent_commit_sha}\n"
        f"author {author} {timestamp} {timezone}\n"
        f"committer {committer} {timestamp} {timezone}\n\n"
        f"{message}\n"
    ).encode()
    
    header = f"commit {len(commit_content)}\0".encode()
    store = header + commit_content
    
    sha1 = hashlib.sha1(store).hexdigest()
    
    dir_name = sha1[:2]
    file_name = sha1[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    if not os.path.exists(os.path.join(".git", "objects", dir_name)):
        os.mkdir(os.path.join(".git", "objects", dir_name))
    
    compressed_data = zlib.compress(store)
    
    with open(object_path, "wb") as f:
        f.write(compressed_data)
    
    return sha1

if __name__ == "__main__":
    main()