import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter

cloud = importlib.import_module("cloud_test")

#================================================================
# Manifest

def DimSanitize(arg):
    return str(arg).replace("@", "@@").replace(",", "@,").replace(";", "@;")

#================================================================
# Content Hashes

content_hashes = []         #store only hashes (salt is applied elsewhere)
content_hashes_stay = []    #store only Booleans to mark if cloud stored content is still up to date
is_update = False
new_content_hashes = []     #store only hashees (salt is applied during the replace process)
new_content_indexes = []

def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.digest()

def RegisterContent(file_path):
    hash_bytes = sha256_file(file_path)
    if is_update:
        try:
            # old content is allowed to stay unchanged on the cloud
            content_hashes_stay[content_hashes.index(hash_bytes)] = True
        except ValueError:
            # new hash found
            new_content_hashes.append(hash_bytes)
    else:
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
                        WriteObject("*content", -(id + 1))
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

#================================================================
# Main


# check if update
if cloud.download(0, "combined.bin"):
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
        #perform
        print("hashes don't match")
    else:
        #load hashes
        file_combined = open("combined.bin", "r", encoding="utf-8")
        dimp = Dimperpreter(file_combined)
        section = ""
        while True:
            #read args
            args = dimp.Next()
            if not args:
                break
            command = args[0].strip()

            #check end of current section
            if command == "section":
                match section:
                    case "hashes":
                        break
                #update section
                section = args[1].strip()

            #states
            match section:
                case "hashes":
                    if command == "section":
                        #init
                        print("Reading hashes")
                    else:
                        #register hash
                        content_hashes.append(bytes.fromhex(args[0]))
                        content_hashes_stay.append(False)
        #close dimp
        file_combined.close()
        del dimp
        #all hashes are now loaded
        print("Loaded " + str(len(content_hashes)) + " content hashes.")
        #mark update flag
        is_update = True

if is_update:
    # Update

    # Generate objects.dim
    ScanObjects("./test_source")

    #start writing hashes.dim
        # Insert new hashes in place of unused

        # Remove content that no longer serves
        # or
        # Add more new content
    # stop writing hashes.dim

    #start rewriting objects.dim

else:
    # First Upload:

    # init file hashes
    file_hashes = open("hashes.dim", "w")
    file_hashes.write("section,information;\n")
    file_hashes.write("title," + DimSanitize("Example Title") + ";\n")
    file_hashes.write("section,hashes;\n")

    # Generate objects.dim
    ScanObjects("./test_source")

    # close hashes
    file_hashes.close()

# Finishing
PackManifest()
cloud.upload(0, "combined.bin")