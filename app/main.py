import sys
import os
import zlib
import hashlib

def main():
    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")
    elif command == "cat-file" and sys.argv[2] == "-p":
        blob_sha = sys.argv[3]
        read_blob(blob_sha)
    elif command == "hash-object" and sys.argv[2] == "-w":
        file_path = sys.argv[3]
        hash_object(file_path)
    elif command == "ls-tree" and sys.argv[2] == "--name-only":
        tree_sha = sys.argv[3]
        ls_tree(tree_sha)
    else:
        raise RuntimeError(f"Unknown command #{command}")

def read_blob(blob_sha):
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
    
    print(sha1)

def ls_tree(tree_sha):
    dir_name = tree_sha[:2]
    file_name = tree_sha[2:]
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    with open(object_path, "rb") as f:
        compressed_data = f.read()
        decompressed_data = zlib.decompress(compressed_data)
    
    # Skip the header
    null_byte_index = decompressed_data.index(b'\x00')
    entries_data = decompressed_data[null_byte_index + 1:]
    
    entries = []
    i = 0
    while i < len(entries_data):
        # Read mode
        mode_end = entries_data.index(b' ', i)
        mode = entries_data[i:mode_end].decode()
        i = mode_end + 1
        
        # Read name
        name_end = entries_data.index(b'\x00', i)
        name = entries_data[i:name_end].decode()
        i = name_end + 1
        
        # Read SHA (20 bytes)
        sha = entries_data[i:i + 20]
        i += 20
        
        entries.append((mode, name, sha))
    
    # Print names only
    for entry in entries:
        print(entry[1])

if __name__ == "__main__":
    main()