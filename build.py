import datetime
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
TABLES = ROOT / "installer" / "tables"
FILES = ROOT / "installer" / "files"
DIST = ROOT / "dist"
RT_VERSION = 16


def read_version():
    text = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+(\.\d+){2,3}", text):
        sys.exit(f"VERSION holds '{text}', expected major.minor.patch")
    return text


def file_version(version):
    parts = [int(p) for p in version.split(".")]
    return parts + [0] * (4 - len(parts))


class Table:
    def __init__(self, text, name):
        newline = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(newline)
        self.name = name
        self.head = lines[:3]
        columns = self.head[0].count("\t")
        self.rows = []
        current = None
        for line in lines[3:]:
            if current is None and not line:
                continue
            current = line if current is None else current + newline + line
            if current.count("\t") >= columns:
                self.rows.append(current.split("\t"))
                current = None
        if current is not None:
            sys.exit(f"{name} ends in the middle of a row")

    @classmethod
    def load(cls, path):
        return cls(path.read_bytes().decode("cp1252"), path.name)

    def save(self, path):
        lines = list(self.head)
        for row in self.rows:
            fields = [field.replace("\r\n", "\x11\x19").replace("\n", "\0") for field in row]
            if any("\r" in field for field in fields):
                sys.exit(f"{self.name} holds a carriage return the installer format cannot carry")
            lines.append("\t".join(fields))
        path.write_bytes(("\r\n".join(lines) + "\r\n").encode("cp1252"))


class Block:
    def __init__(self, key, kind, value, children):
        self.key = key
        self.kind = kind
        self.value = value
        self.children = children


def align(n):
    return (n + 3) & ~3


def parse_block(data, start):
    length, value_length, kind = struct.unpack_from("<HHH", data, start)
    end = start + length
    key_end = start + 6
    while data[key_end:key_end + 2] != b"\0\0":
        key_end += 2
    key = data[start + 6:key_end].decode("utf-16-le")
    pos = start + align(key_end + 2 - start)
    size = min(value_length * 2 if kind == 1 else value_length, end - pos)
    value = data[pos:pos + size]
    pos = start + align(pos + size - start)
    children = []
    while pos < end:
        child, child_length = parse_block(data, pos)
        children.append(child)
        pos = start + align(pos + child_length - start)
    return Block(key, kind, value, children), length


def build_block(block):
    out = bytearray(6)
    out += block.key.encode("utf-16-le") + b"\0\0"
    out += b"\0" * (align(len(out)) - len(out))
    out += block.value
    for child in block.children:
        out += b"\0" * (align(len(out)) - len(out))
        out += build_block(child)
    value_length = len(block.value) // 2 if block.kind == 1 else len(block.value)
    struct.pack_into("<HHH", out, 0, len(out), value_length, block.kind)
    return bytes(out)


def walk(block):
    yield block
    for child in block.children:
        yield from walk(child)


def stamp(source, target, version):
    numbers = file_version(version)
    text = ", ".join(str(n) for n in numbers)
    pe = pefile.PE(str(source))
    data = bytearray(pe.__data__)
    entries = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == RT_VERSION]
    if len(entries) != 1:
        sys.exit(f"{source} has no single version resource")
    leaf = entries[0].directory.entries[0].directory.entries[0].data
    offset = pe.get_offset_from_rva(leaf.struct.OffsetToData)
    size = leaf.struct.Size
    root, length = parse_block(bytes(data[offset:offset + size]), 0)
    if build_block(root) != bytes(data[offset:offset + length]):
        sys.exit(f"{source} has a version resource this build cannot rewrite")
    fixed = bytearray(root.value)
    ms = (numbers[0] << 16) | numbers[1]
    ls = (numbers[2] << 16) | numbers[3]
    struct.pack_into("<IIII", fixed, 8, ms, ls, ms, ls)
    root.value = bytes(fixed)
    for block in walk(root):
        if block.kind == 1 and block.key in ("FileVersion", "ProductVersion"):
            block.value = (text + "\0").encode("utf-16-le")
    rebuilt = build_block(root)
    if len(rebuilt) > size:
        sys.exit(f"{source} has no room for version {version}")
    data[offset:offset + size] = rebuilt + b"\0" * (size - len(rebuilt))
    if len(rebuilt) != length:
        struct.pack_into("<I", data, leaf.struct.get_file_offset() + 4, len(rebuilt))
    pe.close()
    pe = pefile.PE(data=bytes(data))
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    target.write_bytes(pe.write())
    pe.close()


def read_stamp(path):
    pe = pefile.PE(str(path))
    info = pe.VS_FIXEDFILEINFO[0]
    numbers = [info.FileVersionMS >> 16, info.FileVersionMS & 0xFFFF, info.FileVersionLS >> 16, info.FileVersionLS & 0xFFFF]
    strings = {}
    for entry in pe.FileInfo[0]:
        for table in getattr(entry, "StringTable", []):
            strings.update({k.decode(): v.decode() for k, v in table.entries.items()})
    checksum_ok = pe.OPTIONAL_HEADER.CheckSum == pe.generate_checksum()
    pe.close()
    return numbers, strings, checksum_ok


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"{' '.join(map(str, args))} failed:\n{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}")
    return result.stdout


def build(version):
    tables = {path.stem: Table.load(path) for path in sorted(TABLES.glob("*.idt"))}
    properties = {row[0]: row[1] for row in tables["Property"].rows}
    numbers = file_version(version)
    values = {
        "@VERSION@": version,
        "@FILEVERSION@": ".".join(str(n) for n in numbers),
        "@PRODUCTCODE@": "{%s}" % str(uuid.uuid5(uuid.UUID(properties["UpgradeCode"]), "ProductCode " + version)).upper(),
        "@PACKAGECODE@": "{%s}" % str(uuid.uuid4()).upper(),
        "@TIMESTAMP@": datetime.datetime.now(datetime.timezone.utc).strftime("%Y/%m/%d %H:%M:%S"),
    }

    work = Path(tempfile.mkdtemp(prefix="nsm-build-"))
    try:
        cab = work / "cab"
        cab.mkdir()
        for row in tables["File"].rows:
            target = cab / row[0]
            stamp(FILES / row[1] / row[2].split("|")[-1], target, version)
            row[3] = str(target.stat().st_size)

        out = work / "tables"
        out.mkdir()
        for name, table in tables.items():
            for row in table.rows:
                for i, field in enumerate(row):
                    for key, value in values.items():
                        field = field.replace(key, value)
                    if re.search(r"@[A-Z]+@", field):
                        sys.exit(f"{name}.idt still holds a placeholder")
                    row[i] = field
            table.save(out / f"{name}.idt")
        for folder in TABLES.iterdir():
            if folder.is_dir():
                shutil.copytree(folder, out / folder.name)

        cabinet = tables["Media"].rows[0][3].lstrip("#")
        order = [row[0] for row in sorted(tables["File"].rows, key=lambda r: int(r[7]))]
        run("gcab", "-c", "-z", "-n", str(work / cabinet), *order, cwd=cab)

        DIST.mkdir(exist_ok=True)
        msi = DIST / ("netspeedmonitor_%s_x64_setup.msi" % version.replace(".", "_"))
        if msi.exists():
            msi.unlink()
        imports = []
        for name in tables:
            if name != "_SummaryInformation":
                imports += ["-i", f"{name}.idt"]
        run("msibuild", str(msi), *imports, cwd=out)
        run("msibuild", str(msi), "-a", cabinet, str(work / cabinet), cwd=out)
        run("msibuild", str(msi), "-i", "_SummaryInformation.idt", cwd=out)
        return msi
    finally:
        shutil.rmtree(work, ignore_errors=True)


def export(msi, table):
    return Table(run("msiinfo", "export", str(msi), table).decode("cp1252"), table)


def verify(msi, version):
    numbers = file_version(version)
    text = ", ".join(str(n) for n in numbers)
    problems = []
    properties = {row[0]: row[1] for row in export(msi, "Property").rows}
    if properties.get("ProductVersion") != version:
        problems.append(f"ProductVersion is {properties.get('ProductVersion')}")
    if version not in properties.get("ProductName", ""):
        problems.append(f"ProductName is {properties.get('ProductName')}")
    work = Path(tempfile.mkdtemp(prefix="nsm-verify-"))
    try:
        cabinet = export(msi, "Media").rows[0][3].lstrip("#")
        (work / cabinet).write_bytes(run("msiinfo", "extract", str(msi), cabinet))
        files = work / "files"
        files.mkdir()
        run("gcab", "-x", "-C", str(files), str(work / cabinet))
        rows = export(msi, "File").rows
        if not rows:
            problems.append("the installer lists no files")
        for row in rows:
            path = files / row[0]
            if not path.is_file():
                problems.append(f"{row[0]} is missing from {cabinet}")
                continue
            if row[3] != str(path.stat().st_size) or row[4] != ".".join(str(n) for n in numbers):
                problems.append(f"{row[0]} is listed with size {row[3]} and version {row[4]}")
            stamped, strings, checksum_ok = read_stamp(path)
            if stamped != numbers:
                problems.append(f"{row[0]} carries file version {stamped}")
            for key in ("FileVersion", "ProductVersion"):
                if strings.get(key) != text:
                    problems.append(f"{row[0]} carries {key} '{strings.get(key)}'")
            if not checksum_ok:
                problems.append(f"{row[0]} has a wrong PE checksum")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if problems:
        sys.exit(f"Built installer disagrees with VERSION {version}:\n" + "\n".join(problems))


def main():
    version = read_version()
    msi = build(version)
    verify(msi, version)
    print(msi.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
