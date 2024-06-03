# My Git Implementation

In this challenge, you'll build a small Git implementation that's capable of
initializing a repository, creating commits and cloning a public repository.
Along the way we'll learn about the `.git` directory, Git objects (blobs,
commits, trees etc.), Git's transfer protocols and more.



# Passing the first stage

The entry point for your Git implementation is in `app/main.py`. Study and
uncomment the relevant code, and push your changes to pass the first stage:

```sh
git add .
git commit -m "pass 1st stage" # any msg
git push origin master
```

That's all!

# Stage 2 & beyond

Note: This section is for stages 2 and beyond.

1. Ensure you have `python` installed locally
1. Run `./your_git.sh` to run your Git implementation, which is implemented in
   `app/main.py`.
1. Commit your changes and run `git push origin master` to submit your solution
   to CodeCrafters. Test output will be streamed to your terminal.

# Testing locally

The `your_git.sh` script is expected to operate on the `.git` folder inside the
current working directory. If you're running this inside the root of this
repository, you might end up accidentally damaging your repository's `.git`
folder.

We suggest executing `your_git.sh` in a different folder when testing locally.
For example:

```sh
mkdir -p /tmp/testing && cd /tmp/testing
/path/to/your/repo/your_git.sh init
```

To make this easier to type out, you could add a
[shell alias](https://shapeshed.com/unix-alias/):

```sh
alias mygit=/path/to/your/repo/your_git.sh

mkdir -p /tmp/testing && cd /tmp/testing
mygit init
```

## Commands

### `init`
Initializes a new git repository.

**Usage:**
```sh
$ python main.py init
cat-file
Reads a blob object from the git repository and prints its content.

Usage:

$ python main.py cat-file -p <blob_sha>

Example:


$ python main.py cat-file -p e88f7a929cd70b0274c4ea33b209c97fa845fdbc
hello world


--
# My Git Implementation

This project is a simplified implementation of some core Git functionalities. The current implementation supports initializing a new Git repository, reading blob objects, and creating blob objects.

## Commands

### `init`
Initializes a new git repository.

**Usage:**
```sh
$ python main.py init
```

**Description:**
- Creates a `.git` directory with the necessary subdirectories and files.
- Initializes the repository with a default `HEAD` pointing to `refs/heads/main`.

### `cat-file`
Reads a blob object from the git repository and prints its content.

**Usage:**
```sh
$ python main.py cat-file -p <blob_sha>
```

**Example:**
```sh
$ python main.py cat-file -p e88f7a929cd70b0274c4ea33b209c97fa845fdbc
hello world
```

**Description:**
- Reads the contents of the blob object file from the `.git/objects` directory.
- Decompresses the contents using Zlib.
- Extracts the actual content from the decompressed data.
- Prints the content to stdout.

### `hash-object`
Computes the SHA-1 hash of a file and writes the blob object to the git repository.

**Usage:**
```sh
$ python main.py hash-object -w <file_path>
```

**Example:**
```sh
$ echo "hello world" > test.txt
$ python main.py hash-object -w test.txt
3b18e512dba79e4c8300dd08aeb37f8e728b8dad
```

**Description:**
- Reads the contents of the specified file.
- Creates the blob object format: `blob <size>\0<content>`.
- Computes the SHA-1 hash of the blob object.
- Compresses the blob object using Zlib.
- Writes the compressed blob object to the `.git/objects` directory.
- Prints the SHA-1 hash to stdout.

## Example Workflow

1. Initialize a new git repository:
    ```sh
    $ python main.py init
    Initialized git directory
    ```

2. Create a file and compute its SHA-1 hash:
    ```sh
    $ echo "hello world" > test.txt
    $ python main.py hash-object -w test.txt
    3b18e512dba79e4c8300dd08aeb37f8e728b8dad
    ```

3. Read the blob object:
    ```sh
    $ python main.py cat-file -p 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
    hello world
    ```

## Notes

- The `cat-file` command must not append a newline to the output.
- The SHA-1 hash for the `hash-object` command is computed over the uncompressed contents of the file.
- The input for the SHA-1 hash is the header (`blob <size>\0`) + the actual contents of the file.

## Requirements

- Python 3.x
- Zlib library (usually included with Python)

## License

This project is licensed under the MIT License.
```

This `README.md` provides a comprehensive overview of the project, including usage examples and descriptions for each command. If you need any further modifications or additional sections, please let me know!