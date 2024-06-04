



# Git Implementation

This is an implementation of some core Git functionalities. It allows you to initialize a repository, hash objects, list tree contents, write trees, commit trees, and clone repositories to demonstrate the inner workings of Git.

## Features

- Initialize a new Git repository
- Hash files and create Git objects
- List the contents of a tree object
- Write the current directory tree to a tree object
- Create a commit object
- Clone a remote repository

## Requirements

- Python 3.7+
- Standard Python libraries: `contextlib`, `dataclasses`, `datetime`, `functools`, `hashlib`, `operator`, `os`, `shutil`, `sys`, `urllib.request`, `zlib`
- Internet connection for cloning remote repositories

## Usage

### Initialize a Repository

To initialize a new Git repository:

```sh
python simple_git.py init
```

This will create a `.git` directory with the necessary subdirectories and files. Specifically, it creates:

- `.git/objects`: Directory to store Git objects.
- `.git/refs`: Directory to store references to branches.
- `.git/HEAD`: File to store the reference to the current branch.

### Hash a File

To hash a file and optionally save it as a Git object:

```sh
python simple_git.py hash-object -w <filename>
```

This will compute the SHA-1 hash of the file and save it as a Git object in the `.git/objects` directory. The `-w` flag indicates that the file should be written to the object store.

### List Tree Contents

To list the contents of a tree object:

```sh
python simple_git.py ls-tree --name-only <tree_sha1>
```

This will print the names of the files in the specified tree object. The `--name-only` flag indicates that only the names of the files should be printed.

### Write Tree

To write the current directory tree to a tree object:

```sh
python simple_git.py write-tree
```

This will create a tree object representing the current directory structure and print its SHA-1 hash. The tree object will be stored in the `.git/objects` directory.

### Commit Tree

To create a commit object:

```sh
python simple_git.py commit-tree <tree_sha1> -p <parent_sha1> -m <message>
```

This will create a commit object with the specified tree, parent, and message, and print its SHA-1 hash. The `-p` flag specifies the parent commit, and the `-m` flag specifies the commit message.

### Clone a Repository

To clone a remote repository:

```sh
python simple_git.py clone <url> <folder>
```

This will clone the repository from the specified URL into the specified folder. The clone operation involves fetching the repository's objects and references and setting up the working directory.

## Code Overview

### `init(create_ref=True)`

Initializes a new Git repository by creating the necessary directories and files. If `create_ref` is `True`, it also creates a `.git/HEAD` file pointing to the `main` branch.

### `cat_file()`

Displays the content of a Git object specified by its SHA-1 hash. It reads the object from the `.git/objects` directory, decompresses it, and prints its content.

### `hash_object(filename: str = None, save: bool = True) -> str`

Hashes a file and optionally saves it as a Git object. It reads the file content, computes its SHA-1 hash, compresses the content, and optionally saves it in the `.git/objects` directory. Returns the SHA-1 hash of the file.

### `ls_tree()`

Lists the contents of a tree object specified by its SHA-1 hash. It reads the tree object from the `.git/objects` directory, decompresses it, and prints the names of the files in the tree.

### `write_tree(path: str) -> str`

Writes the current directory tree to a tree object and returns its SHA-1 hash. It recursively scans the directory, hashes the files, and creates a tree object representing the directory structure. The tree object is saved in the `.git/objects` directory.

### `commit_tree()`

Creates a commit object with the specified tree, parent, and message, and returns its SHA-1 hash. It constructs the commit content, computes its SHA-1 hash, compresses the content, and saves it in the `.git/objects` directory.

### `clone()`

Clones a remote repository from the specified URL into the specified folder. It fetches the repository's objects and references, sets up the `.git` directory, and restores the working directory.

### `restore_working_dir(tree_ref: str, o_store: dict[str, GitObject], path: str = "", mode: int = 0)`

Restores the working directory from a tree object. It recursively reads the tree object, restores the files and directories, and sets their permissions.

### `collect_entries(path=".") -> list[os.DirEntry]`

Collects all entries (files and directories) in the specified directory, excluding the `.git` directory. It returns a list of `os.DirEntry` objects representing the entries.

### `restore_index()`

Restores the index from the working directory. It collects all entries in the working directory, hashes the files, and writes the index file in the `.git` directory.

### `main()`

Main function to handle different Git commands. It parses the command-line arguments and calls the appropriate function based on the command.

