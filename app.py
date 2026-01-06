import os
import stat
import hashlib
from pathlib import Path

def last_n_path(path, n):
    return "/".join(Path(path).parts[-n:])

#Hardlinks should be forbidden
def is_hardlink(path):
    st = os.stat(path)
    return st.st_nlink > 1


def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


HOME_DIR = "./test"
print("base", HOME_DIR)

count = 0
countNameSizes = 0
last_root=HOME_DIR
for root, dirs, files in os.walk(HOME_DIR, onerror=lambda e: None, followlinks=False):

    #check what kind of step
    if last_root != root:
        if root.count('/') == last_root.count('/'):
            print("out;")
        print("in:", os.path.basename(root))
        last_root = root

    #register dir info
    #print("f")

    #study files
    for name in files:
        path = os.path.join(root, name)
        try:
            st = os.lstat(path)

            #print("name:", name)
            #print("stat:", [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns])
            #cases
            if stat.S_ISREG(st.st_mode):
                #file
                #print("content:", sha256_file(path))
                1
            if stat.S_ISLNK(st.st_mode):
                #link
                #print("symlink:", os.readlink(path))
                1


            count += 1
            countNameSizes += len(name)
            if count % 500 == 0:
                print(count, countNameSizes)
                exit(0)
            #print(f"{path} - {size} bytes")
        except (PermissionError, FileNotFoundError):
            pass