import os
import stat
import hashlib

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


HOME_DIR = "/home/kebabmaster/"
print("base", HOME_DIR)

count = 0
countNameSizes = 0
last_root=HOME_DIR
for root, dirs, files in os.walk(HOME_DIR, onerror=lambda e: None, followlinks=False):
    for name in files:
        path = os.path.join(root, name)
        if last_root != root:
            print("cd", os.path.basename(root))
            last_root = root
        try:
            st = os.stat(path)
            print(st)
            #print(name)
            if os.path.islink(path):
                print("l", name)
                print(st.mode, st.uid)
                exit(0)
                
            else:
                print("f", name, os.path.getsize(path), sha256_file(path))


            count += 1
            countNameSizes += len(name)
            if count % 10000 == 0:
                print(count, countNameSizes)
            #print(f"{path} - {size} bytes")
        except (PermissionError, FileNotFoundError):
            pass