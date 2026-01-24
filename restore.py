import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter
import struct
import json

BUFFER_SIZE = 8192
INTEGRITY_HASH_LENGTH = 32
SALT_LENGTH = 1024

FILENAME_COMBINED_FINAL = "restore_combined.bin"
FILENAME_COMBINED_ENCRYPTED = "restore_combined_cut.bin"
FILENAME_COMBINED = "combined.bin"

#================================================================
# Load config and modules

with open("restore.config.json", "r") as f:
    config = json.load(f)

crypto = importlib.import_module(config["crypto"]["module"])
crypto.initialize(config["crypto"]["config"])
cloud = importlib.import_module(config["cloud"]["module"])
cloud.initialize(config["cloud"]["config"])

def DecryptFile(file_path, output_path, expectedHash):
    with open(file_path, "r+b") as f:
        f.seek(0, 2)              # move to end
        file_size = f.tell()

        read_size = min(SALT_LENGTH, file_size)
        f.seek(file_size - read_size)

        salt = f.read(read_size) # read last bytes
        f.truncate(file_size - read_size)
    #check hash
    if expectedHash != salt:
        print("REPLAY ATTACK on MANIFEST or CONTENT has been detected!!!")
    #decrypt
    crypto.decrypt(file_path, output_path, salt)

SALT_LENGTH = int(config["crypto"]["saltLength"])

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
cloud.download(0, FILENAME_COMBINED_FINAL)

#read manifest
integrity_hash = None
salt = None
#read and cut salt
with open(FILENAME_COMBINED_FINAL, "rb") as src:
    size = os.path.getsize(FILENAME_COMBINED_FINAL)
    data_size = size - SALT_LENGTH
    # Read the salt from the end
    src.seek(size - SALT_LENGTH)
    salt = src.read(SALT_LENGTH)

    # Open destination file for writing
    with open(FILENAME_COMBINED_ENCRYPTED, "wb") as dst:
        src.seek(0)
        remaining = data_size
        while remaining > 0:
            chunk_size = min(BUFFER_SIZE, remaining)
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
#decrypt
crypto.decrypt(FILENAME_COMBINED_ENCRYPTED, FILENAME_COMBINED, salt)
#read and cut integrity hash
with open(FILENAME_COMBINED, "r+b") as f:
    size = os.path.getsize(FILENAME_COMBINED)
    f.seek(size - INTEGRITY_HASH_LENGTH)
    integrity_hash = f.read(INTEGRITY_HASH_LENGTH)   # read the tail
    f.truncate(size - INTEGRITY_HASH_LENGTH)     # remove it
#check integrity_hash
if sha256_file(FILENAME_COMBINED) != integrity_hash:
    print("hashes don't match")
    exit(1)

#start recovering the data
file_combined = open(FILENAME_COMBINED, "r", encoding="utf-8")
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
                        #crypto.decrypt("temp.bin", "temp_decrypted.bin", p[0])
                        DecryptFile("temp.bin", "temp_decrypted.bin", p[0])
                        os.replace("temp_decrypted.bin", "temp.bin")
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


#================================================================
# Cleaning

#delete saved files
def DeleteFile(path):
    try:
        os.remove(path)
    except:
        0
DeleteFile(FILENAME_COMBINED_FINAL)
DeleteFile(FILENAME_COMBINED_ENCRYPTED)
DeleteFile(FILENAME_COMBINED)

