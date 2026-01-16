import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter
import struct
import json

#================================================================
# Load config and modules

with open("backup.config.json", "r") as f:
    config = json.load(f)

crypto = importlib.import_module(config["crypto"]["module"])
crypto.initialize(config["crypto"]["config"])
cloud = importlib.import_module(config["cloud"]["module"])
cloud.initialize(config["cloud"]["config"])

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

#read headers
file_combined = open("combined.bin", "rb")
integrity_hash = file_combined.read(32)
length = struct.unpack("I", file_combined.read(4))[0]
salt = file_combined.read(length)
file_combined.close()
#cut headers
CUT = (0 + 32) + (4 + length)
with open("combined.bin", "rb") as src, open("combined_cut.bin", "wb") as dst:
    src.seek(CUT)
    shutil.copyfileobj(src, dst)
os.replace("combined_cut.bin", "combined.bin")
#decrypt
crypto.decrypt("combined.bin", "combined_decrypted.bin", salt)
os.replace("combined_decrypted.bin", "combined.bin")

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
current_dir = config["targetRestoreDirectory"]
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
                print("Loaded", len(content_salt), "salts.")
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
                content_salt.append([bytes.fromhex(args[1]), None])
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
                elif command == "object":
                    current_target = os.path.join(current_dir, args[1])
                elif command == "stat":
                    #apply meta
                    if stat.S_ISLNK(os.lstat(current_target).st_mode):
                        #for links
                        os.lchown(current_target, int(args[4]), int(args[5]))
                    else:
                        #for rest
                        os.chmod(current_target, int(args[3]))
                        os.chown(current_target, int(args[4]), int(args[5]))
                    #apply time meta
                    os.utime(current_target, ns=(int(args[8]), int(args[8])), follow_symlinks=False)
                elif command == "content":
                    #get salt
                    p = content_salt[int(args[1])]
                    if p[1] != None:
                        #copy cached
                        shutil.copyfile(p[1], current_target)
                    else:
                        #download
                        cloud.download(int(args[1]) + 1, "temp.bin")
                        #decrypt
                        salt = p[0]
                        crypto.decrypt("temp.bin", "temp_decrypted.bin", p[0])
                        os.replace("temp_decrypted.bin", "temp.bin");
                        #paste
                        shutil.copyfile("temp.bin", current_target)
                        #cache
                        p[1] = current_target
                elif command == "symlink":
                    try:
                        os.symlink(args[1], current_target, target_is_directory=(args[2]=="True"))
                    except FileExistsError:
                        os.unlink(current_target)
                        os.symlink(args[1], current_target, target_is_directory=(args[2]=="True"))



                0


