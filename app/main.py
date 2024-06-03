import sys
import os
import zlib

def main():
    print("Logs from your program will appear here!")

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
    else:
        raise RuntimeError(f"Unknown command #{command}")

def read_blob(blob_sha):
    # The first two characters of the SHA-1 hash are the directory name
    dir_name = blob_sha[:2]
    # The remaining 38 characters are the file name
    file_name = blob_sha[2:]
    # Construct the path to the object file
    object_path = os.path.join(".git", "objects", dir_name, file_name)
    
    # Read and decompress the object file
    with open(object_path, "rb") as f:
        compressed_data = f.read()
        decompressed_data = zlib.decompress(compressed_data)
    
    # Extract the content from the decompressed data
    null_byte_index = decompressed_data.index(b'\x00')
    content = decompressed_data[null_byte_index + 1:]
    
    # Print the content to stdout without a newline at the end
    sys.stdout.buffer.write(content)

if __name__ == "__main__":
    main()