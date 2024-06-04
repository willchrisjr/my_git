import contextlib
import dataclasses
import datetime
import functools
import hashlib
import operator
import os
import shutil
import sys
import urllib.request
import zlib
from typing import Iterator
from typing import Union


def init(create_ref=True):
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    if create_ref:
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")


def cat_file():
    p = sys.argv[2]
    revision = sys.argv[3]
    assert p == "-p"

    folder, file = revision[:2], revision[2:]
    with open(f".git/objects/{folder}/{file}", "rb") as f:
        compressed = f.read()
    raw_content = zlib.decompress(compressed)

    header: bytes
    content: bytes
    header, content = raw_content.split(b"\0", maxsplit=1)

    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == "blob"
    assert size == len(content)

    # Raw bytes output:
    sys.stdout.buffer.write(content)
    sys.stdout.flush()


def hash_object(filename: str = None, save: bool = True) -> str:
    if filename is None:
        w = sys.argv[2]
        filename = sys.argv[3]
        assert w == "-w"

    with open(filename, "rb") as f:
        content = f.read()

    size = len(content)
    header = f"blob {size}".encode()
    raw_content = header + b"\0" + content
    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    if save:
        os.makedirs(f".git/objects/{folder}", exist_ok=True)
        with open(f".git/objects/{folder}/{file}", "wb") as f:
            f.write(compressed)
    return digest


def ls_tree():
    no = sys.argv[2]
    revision = sys.argv[3]
    assert no == "--name-only"

    # TODO: same code
    folder, file = revision[:2], revision[2:]
    with open(f".git/objects/{folder}/{file}", "rb") as f:
        compressed = f.read()
    raw_content = zlib.decompress(compressed)

    header: bytes
    content: bytes
    header, content = raw_content.split(b"\0", maxsplit=1)
    file_type: str
    size_raw: str
    file_type, size_raw = header.decode().split(maxsplit=1)
    size = int(size_raw)
    assert file_type == "tree"
    assert size == len(content)

    res = _ls_tree(content)

    for r in res:
        print(r.name)


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitFile:
    name: str
    mode: int
    digest: str


def _ls_tree(content: bytes) -> list[GitFile]:
    res = []
    while True:
        if not content:
            break
        file_header: bytes
        rest: bytes
        file_sha: bytes
        file_header, rest = content.split(b"\0", maxsplit=1)
        file_sha, content = rest[:20], rest[20:]
        mode_raw, filename = file_header.decode().split()
        mode = int(mode_raw, 8)
        hex_digest = file_sha.hex()
        res.append(GitFile(name=filename, mode=mode, digest=hex_digest))
        # print(mode, filename, hex_digest)
    return res


def write_tree(path: str) -> str:
    entries: dict[str, bytes] = {}
    for entry in os.scandir(path):
        if entry.name == ".git":
            continue

        # digest: str = ''
        # name: str = ''
        # mode: str = ''

        if entry.is_file():
            digest = hash_object(os.path.join(path, entry.name))
            name = entry.name
            #          1   0   0   6   4   4
            mode = 0b001_000_000_110_100_100
            # mode = '100644'
        else:
            digest = write_tree(os.path.join(path, entry.name))
            name = entry.name
            # TODO: not '040000' for some reason
            # TODO: octal format
            #          0   4   0   0   0   0
            mode = 0b000_100_000_000_000_000
            # mode = '40000'

        entries[name] = f"{mode:o} {name}".encode() + b"\0" + bytes.fromhex(digest)

    content: bytes
    result = [value for key, value in sorted(entries.items())]
    content = b"".join(result)

    # Same code
    size = len(content)
    header = f"tree {size}".encode()
    raw_content = header + b"\0" + content

    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", "wb") as f:
        f.write(compressed)
    return digest


def commit_tree():
    tree = sys.argv[2]
    p = sys.argv[3]
    parent = sys.argv[4]
    m = sys.argv[5]
    message = sys.argv[6]
    assert p == "-p"
    assert m == "-m"
    author = "Serhii Charykov <laammaar@gmail.com>"
    timestamp = datetime.datetime.now(tz=datetime.UTC).timestamp()
    # TODO: get proper offset
    tz_offset = "+0000"

    content: bytes = b""
    content += f"tree {tree}\n".encode()
    content += f"parent {parent}\n".encode()
    content += f"author {author} {timestamp} {tz_offset}\n".encode()
    content += f"committer {author} {timestamp} {tz_offset}\n".encode()
    content += f"\n".encode()
    content += message.encode()
    content += f"\n".encode()

    # Same code
    size = len(content)
    header = f"commit {size}".encode()
    raw_content = header + b"\0" + content

    digest = hashlib.sha1(raw_content).hexdigest()
    compressed = zlib.compress(raw_content)

    folder, file = digest[:2], digest[2:]

    os.makedirs(f".git/objects/{folder}", exist_ok=True)
    with open(f".git/objects/{folder}/{file}", "wb") as f:
        f.write(compressed)

    return digest


def parse_lines(data: bytes) -> Iterator[bytes]:
    while True:
        if not data:
            break

        if data.startswith(b"PACK"):
            yield data
            # TODO: what if something after data
            break

        length_raw: bytes
        length_raw, data = data[:4], data[4:]
        length = int.from_bytes(bytes.fromhex(length_raw.decode()))

        if length == 0:
            yield b""
            continue

        length -= 4
        assert length > 0
        assert length < len(data)
        line, data = data[:length], data[length:]
        yield line.rstrip()


def read_length(data: bytes) -> tuple[int, int, bytes]:
    length_raw = ""
    data_type: int = 0
    while True:
        byte, data = data[0], data[1:]

        if not data_type:
            data_type = (byte & 0b0111_0000) >> 4
            length_raw = format(byte & 0b0000_1111, "04b")
        else:
            tmp = format(byte & 0b0111_1111, "07b")
            length_raw = tmp + length_raw

        if not byte & 0b1000_0000:
            break
    result = int(length_raw, 2)
    return result, data_type, data


def read_size(data: bytes) -> tuple[int, bytes]:
    length_raw = ""
    while True:
        byte, data = data[0], data[1:]

        tmp = format(byte & 0b0111_1111, "07b")
        length_raw = tmp + length_raw

        if not byte & 0b1000_0000:
            break
    result = int(length_raw, 2)
    return result, data


TYPES = {
    1: "commit",
    2: "tree",
    3: "blob",
    4: "tag",
    6: "ofs_delta",
    7: "ref_delta",
}


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitObject:
    type: str
    body: bytes

    def save(self):
        # Same code
        size = len(self.body)
        header = f"{self.type} {size}".encode()
        raw_content = header + b"\0" + self.body

        digest = hashlib.sha1(raw_content).hexdigest()
        compressed = zlib.compress(raw_content)

        folder, file = digest[:2], digest[2:]

        os.makedirs(f".git/objects/{folder}", exist_ok=True)
        with open(f".git/objects/{folder}/{file}", "wb") as f:
            f.write(compressed)

    def restore(self, path: str, mode: int):
        head, tail = os.path.split(path)
        if head:
            os.makedirs(head, exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.body)
        os.chmod(path, mode)

    @functools.cached_property
    def digest(self):
        size = len(self.body)
        header = f"{self.type} {size}".encode()
        raw_content = header + b"\0" + self.body

        digest = hashlib.sha1(raw_content).hexdigest()
        return digest


@dataclasses.dataclass(frozen=True, kw_only=True)
class InstructionCopy:
    offset: int
    size: int


@dataclasses.dataclass(frozen=True, kw_only=True)
class InstructionInsert:
    data: bytes


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitRefDelta:
    ref_to: str
    base_size: int
    finish_size: int
    instructions: list[Union[InstructionCopy, InstructionInsert]]  # TOdo: use enums


def parse_offset_size(flags, i, data):
    result = 0
    shift = -8
    for bit in flags:
        shift += 8
        if bit == "0":
            continue
        i += 1
        result |= data[i] << shift

    return i, result


def parse_delta(ref_to: str, data: bytes) -> GitRefDelta:
    i = 0

    base_size, data = read_size(data)
    finish_size, data = read_size(data)
    instructions: list[Union[InstructionCopy, InstructionInsert]] = []
    while i < len(data):
        cur = data[i]

        # Copy
        if cur & 0x80:
            flags = format(cur & 0x7F, "07b")[::-1]
            i, offset = parse_offset_size(flags[:4], i, data)
            i, size = parse_offset_size(flags[4:], i, data)

            # Special case for 0 size
            if not size:
                size = 0x10000

            i += 1
            instructions.append(InstructionCopy(offset=offset, size=size))
        # Insert
        elif cur & 0x7F:
            size = cur & 0x7F
            assert size > 0
            i += 1
            assert i + size <= len(data)  # TODO: <= or <
            new_data = data[i : i + size]
            i += size
            instructions.append(InstructionInsert(data=new_data))

        # Zero
        else:
            raise RuntimeError("Reserved value")

    # Sanity check
    assert i == len(data)

    return GitRefDelta(
        ref_to=ref_to,
        base_size=base_size,
        finish_size=finish_size,
        instructions=instructions,
    )


def parse_data(data: bytes, check_hash: str):
    signature, data = data[:4], data[4:]
    assert signature == b"PACK"

    version_raw, data = data[:4], data[4:]
    version = int.from_bytes(version_raw)
    assert version == 2

    object_count_raw, data = data[:4], data[4:]
    object_count = int.from_bytes(object_count_raw)
    # print(f"{object_count=}")
    o_store: dict[str, GitObject] = {}

    deltas: list[GitRefDelta] = []

    for object_index in range(object_count):
        # print(f"{object_index} {len(data)=}")
        length, data_type, data = read_length(data)
        assert data_type in TYPES, f"Unexpected type {data_type}"
        data_type_str = TYPES[data_type]
        assert data_type != 6  # Happens only if you ask server

        # not delta
        ref_to = ""
        if data_type > 5:
            ref_to_raw, data = data[:20], data[20:]
            ref_to = ref_to_raw.hex()

        dec = zlib.decompressobj()
        decompressed = b""
        while True:
            decompressed += dec.decompress(data)
            if dec.eof:
                data = dec.unused_data
                break
        assert len(decompressed) == length
        # print(data_type_str, ref_to, length, decompressed)
        if data_type < 5:
            o = GitObject(type=data_type_str, body=decompressed)
            o_store[o.digest] = o
            o.save()
        else:
            deltas.append(parse_delta(ref_to, decompressed))

    while deltas:
        for i, delta in enumerate(deltas):
            if delta.ref_to in o_store:
                break
        else:
            raise RuntimeError("Can't resolve smth")

        resolve = deltas[i]
        deltas = deltas[0:i] + deltas[i + 1 :]

        base = o_store[delta.ref_to]
        body = b""
        for instruction in resolve.instructions:
            if isinstance(instruction, InstructionCopy):
                assert (
                    0
                    <= instruction.offset
                    < instruction.offset + instruction.size
                    <= len(base.body)
                )
                body += base.body[
                    instruction.offset : instruction.offset + instruction.size
                ]
                continue
            if isinstance(instruction, InstructionInsert):
                body += instruction.data
                continue
            raise RuntimeError("Invalid Instruction")

        o = GitObject(type=base.type, body=body)
        o_store[o.digest] = o
        o.save()

    assert len(data) == 20
    assert data.hex() == check_hash, "Hash check mismatch"
    return o_store


def prepare_line(s: str) -> bytes:
    if not s:
        return b"0000"
    s += "\n"
    raw = s.encode()
    length = len(raw) + 4
    raw_length = length.to_bytes(2).hex().encode()
    return raw_length + raw


DEBUG = os.environ.get("DEBUG") == "1"
LOCAL = os.environ.get("LOCAL") == "1"


def clone():
    url = sys.argv[2]
    folder = sys.argv[3]

    if DEBUG:
        shutil.rmtree(folder, ignore_errors=True)

    os.makedirs(folder, exist_ok=False)
    with contextlib.chdir(folder):
        init(create_ref=False)
        _clone(url)


def _clone(url: str):
    refs_url = f"{url}/info/refs?service=git-upload-pack"
    if DEBUG:
        with open("../tmp", "rb") as f:
            data = f.read()
    else:
        with urllib.request.urlopen(refs_url) as f:
            data = f.read()
        if LOCAL:
            with open("../tmp", "wb") as f:
                f.write(data)

    refs: dict[str, str] = {}
    capabilities = b""
    for line in parse_lines(data):
        if not line:
            continue
        if line.startswith(b"#"):
            continue
        ref: bytes
        digest: bytes
        rest: bytes
        digest, rest = line.split(b" ", maxsplit=1)
        if not capabilities:
            ref, capabilities = rest.split(b"\0")
            # print(capabilities)
        else:
            ref = rest
        refs[ref.decode()] = digest.decode()

    head_ref = refs["HEAD"]
    # print(refs)
    caps = capabilities.split()
    for cap in caps:
        if cap.startswith(b"symref=HEAD:"):
            head = cap.replace(b"symref=HEAD:", b"").decode()
            with open(".git/HEAD", "w") as f:
                f.write(f"ref: {head}\n")
            break
    else:
        raise RuntimeError("HEAD is unknown")

    os.makedirs(".git/refs/heads/", exist_ok=True)
    for reff, value in refs.items():
        if not reff.startswith("refs/heads/"):
            continue

        with open(f".git/{reff}", "w") as f:
            f.write(value)
            f.write("\n")
        # print(reff, value)

    # print(f"Downloading {head_ref=}")
    data = b""
    data += prepare_line(f"want {head_ref}")
    data += prepare_line("")
    data += prepare_line("done")

    data_url = f"{url}/git-upload-pack"

    if DEBUG:
        with open("../tmp2", "rb") as f:
            data = f.read()
    else:
        with urllib.request.urlopen(data_url, data) as f:
            data = f.read()
        if LOCAL:
            with open("../tmp2", "wb") as f:
                f.write(data)

    lines = list(parse_lines(data))
    assert lines[0] == b"NAK"
    assert lines[1].startswith(b"PACK")
    assert len(lines) == 2

    packed_data = lines[1]
    check_hash = hashlib.sha1(packed_data[:-20]).hexdigest()
    o_store = parse_data(packed_data, check_hash)
    os.makedirs(".git/objects/pack", exist_ok=True)
    with open(f".git/objects/pack/pack-{check_hash}.pack", "wb") as f:
        f.write(packed_data)

    # 2013 behaviour
    # content = '\n'.join(sorted(o_store)) + '\n'
    # print(hashlib.sha1(content.encode()).hexdigest())

    commit = o_store[head_ref]
    for line in commit.body.split(b"\n"):
        if line.startswith(b"tree "):
            tree_ref = line[len("tree ") :].decode()
            break
    else:
        raise RuntimeError("No tree found")

    restore_working_dir(tree_ref, o_store)
    restore_index()


def restore_working_dir(
    tree_ref: str, o_store: dict[str, GitObject], path: str = "", mode: int = 0
):
    o = o_store[tree_ref]
    if o.type == "tree":
        files = _ls_tree(o.body)
        for file in files:
            restore_working_dir(
                file.digest, o_store, os.path.join(path, file.name), file.mode
            )
        return
    if o.type == "blob":
        o.restore(path, mode)
        return
    raise RuntimeError("Unknown object type")


def collect_entries(path=".") -> list[os.DirEntry]:
    files: list[os.DirEntry] = [entry for entry in os.scandir(path) if entry.is_file()]
    dirs: list[os.DirEntry] = [
        entry for entry in os.scandir(path) if entry.is_dir() and entry.name != ".git"
    ]

    entries = files + [
        inner_entry
        for entry in dirs
        for inner_entry in collect_entries(os.path.join(path, entry.name))
    ]
    return entries


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class Entry:
    name: bytes
    digest: str
    entry: os.DirEntry


def restore_index():
    entries = collect_entries()
    sorted_entries = sorted(
        [
            Entry(
                digest=hash_object(entry.path, save=False),
                entry=entry,
                name=entry.path.lstrip("./").rstrip("/").encode(),
            )
            for entry in entries
        ],
        key=operator.attrgetter("name"),
    )
    with open(".git/index", "wb") as f:
        # with open("index", "wb") as f:

        # Header 12 bytes
        f.write(b"DIRC")  # sign
        f.write(int(2).to_bytes(4))  # version 2
        f.write(len(sorted_entries).to_bytes(4))  # number of entries

        # Sorted Entries
        for entry in sorted_entries:
            stat = entry.entry.stat()

            entry_len = 0
            sec, nano = divmod(stat.st_ctime_ns, 10**9)
            entry_len += f.write(sec.to_bytes(4))  # ctime metadata
            entry_len += f.write(nano.to_bytes(4))  # ctime metadata fractions
            sec, nano = divmod(stat.st_mtime_ns, 10**9)
            entry_len += f.write(sec.to_bytes(4))  # mtime file data
            entry_len += f.write(nano.to_bytes(4))  # mtime file data fractions
            entry_len += f.write(stat.st_dev.to_bytes(4))  # stat dev
            entry_len += f.write(stat.st_ino.to_bytes(4))  # ino dev

            entry_len += f.write(b"\0\0")  # 16 bit zero
            reg_file = 0b1000
            value = reg_file << 3
            zero = 0b000
            value = (value | zero) << 9

            # TODO: load permission from store
            # stat.st_mode
            permission = 0o100644 & 0b111_111_111  # only 9 bits
            # permission =
            value |= permission
            entry_len += f.write(value.to_bytes(2))  # permissions
            entry_len += f.write(stat.st_uid.to_bytes(4))  # uid
            entry_len += f.write(stat.st_gid.to_bytes(4))  # gid
            entry_len += f.write(
                (stat.st_size & 0xFFFFFFFF).to_bytes(4)
            )  # 32 bit truncated size
            obj_name = bytes.fromhex(entry.digest)
            assert len(obj_name) == 20
            entry_len += f.write(obj_name)  # 20 bytes sha1

            # assume bit, extended bit, 2 merge bits
            flags = 0b0000 << 4
            name = entry.name
            assert b".git/" not in name
            length = len(name)
            if length > 0xFFF:  # Max 12 bits
                length = 0xFFF
            flags |= length
            entry_len += f.write(flags.to_bytes(2))  # 16bit flags
            entry_len += f.write(name)
            entry_len += f.write(b"\0")  # str NUL terminator
            if entry_len % 8:  # Keep entry 8 bytes aligned
                pad = 8 - (entry_len % 8)
                f.write(b"\0" * pad)


def main():
    command = sys.argv[1]
    if command == "init":
        init()
    elif command == "cat-file":
        cat_file()
    elif command == "hash-object":
        print(hash_object())
    elif command == "ls-tree":
        ls_tree()
    elif command == "write-tree":
        print(write_tree("."))
    elif command == "commit-tree":
        print(commit_tree())
    elif command == "clone":
        clone()
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()