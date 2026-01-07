import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil

cloud = importlib.import_module("cloud_test")

#================================================================
# Manifest

def DimSanitize(arg):
    return str(arg).replace("@", "@@").replace(",", "@,").replace(";", "@;")

#================================================================
# Content Hashes

content_hashes = []

def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.digest()

def RegisterContent(file_path):
    hash_bytes = sha256_file(file_path)
    try:
        return content_hashes.index(hash_bytes)
    except ValueError:
        #encrypt file
        salt = 666
        #upload new content (id=0 reserved for the manifest)
        id = len(content_hashes)
        cloud.upload(id + 1, file_path)
        #add new hash
        content_hashes.append(hash_bytes)
        file_hashes.write(DimSanitize(hash_bytes.hex()) + "," + DimSanitize(salt) + ";\n")
        #return 
        return id

#================================================================
# scan

def cd_up(path_a, path_b):
    a_parts = Path(path_a).resolve().parts
    b_parts = Path(path_b).resolve().parts

    # Find common prefix length
    common_length = 0
    for a, b in zip(a_parts, b_parts):
        if a == b:
            common_length += 1
        else:
            break

    return len(a_parts) - common_length

def ScanObjects(start_path):
    #file
    file_objects = open("objects.dim", "w")

    #funcs
    def WriteObject(*args):
        for i, arg in enumerate(args):
            file_objects.write(DimSanitize(arg))
            if i < len(args) - 1:
                file_objects.write(",")
        file_objects.write(";\n")

    #start scanning
    file_objects.write("section,objects;\n")
    count = 0
    last_root=start_path
    for root, dirs, files in os.walk(start_path, onerror=lambda e: None, followlinks=False):

        #check what kind of step
        if last_root != root:
            r = cd_up(last_root, root)
            if r > 0:
                WriteObject("out", r)
            WriteObject("in", os.path.basename(root))
            last_root = root

        #register dir info
        st = os.lstat(root)
        WriteObject("stat", st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns)

        #study files
        for name in files + dirs:
            path = os.path.join(root, name)
            try:
                #skip next roots (dirs)
                st = os.lstat(path)
                if stat.S_ISDIR(st.st_mode):
                    continue

                #Save data
                WriteObject("object", name)
                #cases
                if stat.S_ISREG(st.st_mode):
                    #file
                    id = RegisterContent(path)
                    if id < 0:
                        #id comes from the new hash list
                        WriteObject("*content", id + 1)
                    else:
                        #hash is ok
                        WriteObject("content", id)
                elif stat.S_ISLNK(st.st_mode):
                    #link
                    WriteObject("symlink", os.readlink(path), os.path.isdir(path))
                else:
                    print("Object type is not supported:", path)
                #write stat
                WriteObject("stat", st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns)

                #log checkpoint
                count += 1
                if count % 1000 == 0:
                    print(count)

                #print(f"{path} - {size} bytes")
            except (PermissionError, FileNotFoundError):
                pass

#================================================================
# Packing

def join_files(file1, file2, output):
    with open(output, "wb") as out:
        for fname in (file1, file2):
            with open(fname, "rb") as f:
                out.write(f.read())

def PackManifest():
    join_files("hashes.dim", "objects.dim", "combined.dim")

    # get integrity hash
    integrity_hash = sha256_file("combined.dim")

    # encrypt combine
    shutil.copy2("combined.dim", "combined.bin")

    # add integrity_hash
    with open("combined.bin", "ab") as out:
        out.write(integrity_hash)

    #upload file
    cloud.upload(0, "combined.bin")

#================================================================
# Main

# init hashes
file_hashes = open("hashes.dim", "w")
file_hashes.write("section,information;\n")
file_hashes.write("title," + DimSanitize("Example Title") + ";\n")
file_hashes.write("section,hashes;\n")

# Generate objects.dim
ScanObjects("./test_source")

# close hashes
file_hashes.close()

# Generate Manifest
PackManifest()