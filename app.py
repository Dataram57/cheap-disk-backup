import os
import stat
import hashlib
from pathlib import Path

#================================================================

file_objects = open("objects.dim", "w")

def DimSanitize(arg):
    return str(arg).replace("@", "@@").replace(",", "@,").replace(";", "@;")

def WriteObject(*args):
    for i, arg in enumerate(args):
        file_objects.write(DimSanitize(arg))
        if i < len(args) - 1:
            file_objects.write(",")
    file_objects.write(";\n")

#================================================================

file_hashes = open("hashes.bin", "ab")

content_hashes = []

def RegisterContent(file_path):
    hash_bytes = sha256_file(file_path)
    try:
        return content_hashes.index(hash_bytes)
    except ValueError:
        #add new hash
        content_hashes.append(hash_bytes)
        file_hashes.write(hash_bytes)
        #register new content
        
        #return 
        return len(content_hashes) - 1

#================================================================

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

#Hardlinks should be forbidden
def is_hardlink(path):
    st = os.stat(path)
    return st.st_nlink > 1


def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.digest()


HOME_DIR = "/home/kebabmaster"
print("base", HOME_DIR)

count = 0
last_root=HOME_DIR
for root, dirs, files in os.walk(HOME_DIR, onerror=lambda e: None, followlinks=False):

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
    
    #print("f")

    #study files
    for name in files:
        path = os.path.join(root, name)
        try:
            st = os.lstat(path)

            WriteObject("name", name)
            WriteObject("stat", st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns)
    #print("f")
            #cases
            if stat.S_ISREG(st.st_mode):
                #file
                WriteObject("content", RegisterContent(path))
                1
            if stat.S_ISLNK(st.st_mode):
                #link
                WriteObject("symlink", os.readlink(path))
                1

            count += 1
            if count % 1000 == 0:
                print(count)


            #print(f"{path} - {size} bytes")
        except (PermissionError, FileNotFoundError):
            pass