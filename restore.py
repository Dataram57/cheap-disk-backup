import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter

base_dir = Path("./test_restore")
cloud = importlib.import_module("cloud_test")

#================================================================
# hashes

def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.digest()

#================================================================
# Main

# download manifest
cloud.download(0, "combined.bin")

#cut integrity hash
cut_size = 32
file_combined = open("combined.bin", "rb+")
# Go to end of file
file_combined.seek(0, os.SEEK_END)
file_combined_size = file_combined.tell()
if file_combined_size < cut_size:
    raise ValueError("File is smaller than 32 bytes")
# Seek to where the last 32 bytes start
file_combined.seek(file_combined_size - cut_size)
# Read the last 32 bytes
integrity_hash = file_combined.read(cut_size)
# Truncate the file to remove those bytes
file_combined.truncate(file_combined_size - cut_size)
file_combined.close()

#decrypt
#...

#check integrity_hash
if sha256_file("combined.bin") != integrity_hash:
    print("hashes don't match")
    exit(1)

#start recovering the data
file_combined = open("combined.bin", "r", encoding="utf-8")
dimp = Dimperpreter(file_combined)
section = None
content_salt = []       #(salt, CachedFile)
current_dir = base_dir
current_target = current_dir
while True:
    #read args
    args = dimp.Next()
    if not args:
        break
    command = args[0].strip()

    #check end of current section
    if command == "section":
        match section:
            case "information":
                0
            case "hashes":
                0
                print("salts:", content_salt)
            case "objects":
                print("end")
                0
        #update section
        section = args[1].strip()

    #states
    match section:
        case "information":
            print(args)
        case "hashes":
            if command == "section":
                #init
                print("reading hashes")
            else:
                #register hash
                content_salt.append([args[1], None])
        case "objects":
            if command == "section":
                #init
                print("reading objects")
            else:
                #walk the tree
                if command == "in":
                    current_dir = os.path.join(current_dir, args[1])
                    current_target = current_dir
                    os.makedirs(current_target, exist_ok=True)
                    print(current_dir)
                elif command == "out":
                    i = int(args[1])
                    while i > 0:
                        i -= 1
                        current_dir = Path(current_dir).parent
                    current_target = current_dir
                elif command == "name":
                    current_target = os.path.join(current_dir, args[1])
                elif command == "stat":
                    
                    0
                elif command == "content":
                    #get salt
                    p = content_salt[int(args[1])]
                    if p[1] != None:
                        #copy cached
                        shutil.copyfile(p[1], current_target)
                    else:
                        #download
                        cloud.download(int(args[1]) + 1, "temp.bin")
                        #paste
                        shutil.copyfile("temp.bin", current_target)
                        #cache
                        p[1] = current_target



                0


