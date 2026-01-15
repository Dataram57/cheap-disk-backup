import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter

cloud = importlib.import_module("cloud_test")
#cloud = importlib.import_module("cloud_boto3")
crypto = importlib.import_module("crypto_dr57_sha256stream")

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
new_content_hashes_mapper = []  #stores only new indexes

def sha256_file(path, chunk_size=8192):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.digest()

def RegisterContent(file_path):
    global file_hashes
    hash_bytes = sha256_file(file_path)
    if is_update:
        try:
            # old content is allowed to stay unchanged on the cloud
            id = content_hashes.index(hash_bytes)
            content_hashes_stay[id] = True
            return id
        except ValueError:
            # hash is new to content_hashes
            try:
                # try to find it in the new_content_hashes
                return -(new_content_hashes.index(hash_bytes) + 1)
            except ValueError:
                # new hash found
                new_content_hashes.append(hash_bytes)
                new_content_hashes_mapper.append(-1)
                return -len(new_content_hashes)
    else:
        try:
            return content_hashes.index(hash_bytes)
        except ValueError:
            #get salt
            salt = crypto.generate_salt()
            #encrypt file
            output_path = "temp_file.bin"
            crypto.encrypt(file_path, output_path, salt)
            #upload new content (id=0 reserved for the manifest)
            id = len(content_hashes)
            cloud.upload(id + 1, output_path)
            #add new hash
            content_hashes.append(hash_bytes)
            file_hashes.write(DimSanitize(hash_bytes.hex()) + "," + DimSanitize(salt.hex()) + ";\n")
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

def ScanObjects(start_path, output_path):
    #file
    file_objects = open(output_path, "w")

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
    crypto.encrypt("combined.dim", "combined.bin")
    #shutil.copy2("combined.dim", "combined.bin")

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
    crypto.decrypt("combined.bin", "combined_decrypted.bin")
    os.replace("combined_decrypted.bin", "combined.bin")

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
    ScanObjects("./test_source", "objects_new.dim")

    #objects.dim
    file_objects = open("objects.dim", "w", encoding="utf-8")
    def WriteObject(args):
        for i, arg in enumerate(args):
            file_objects.write(DimSanitize(arg))
            if i < len(args) - 1:
                file_objects.write(",")
        file_objects.write(";")
    
    #hashes.dim
    upload_id_gen = len(content_hashes)
    file_hashes = open("hashes.dim", "w")
    file_hashes.write("section,information;\n")
    file_hashes.write("title," + DimSanitize("Example Title") + ";\n")
    file_hashes.write("section,hashes;\n")
    file_combined = open("combined.bin", "r", encoding="utf-8")
    dimp_hashes = Dimperpreter(file_combined)
    #scope to hashes
    while True:
        args = dimp_hashes.Next()
        if len(args) == 0:
            print("COURRPTED MANIFEST")
            exit(0)
        if args[0].strip() == "section":
            if args[1] == "hashes":
                break
    #function for writing
    file_hashes_next_id = 0
    def WriteNextHashes(count):
        global file_hashes_next_id
        while count > 0:
            count -= 1
            args = dimp_hashes.Next()
            file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1]) + ";\n")
            file_hashes_next_id += 1
    def SkipHash():
        global file_hashes_next_id
        dimp_hashes.Next()
        file_hashes_next_id += 1

    #scan objects_new.dim
    file_objects_new = open("objects_new.dim", "r", encoding="utf-8")
    dimp = Dimperpreter(file_objects_new)
    section = ""
    current_dir = "./test_source"
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
                case "objects":
                    break
            #update section
            section = args[1].strip()

        #states
        match section:
            case "objects":
                #current_target
                if command == "in":
                    current_dir = os.path.join(current_dir, args[1])
                    current_target = current_dir
                elif command == "out":
                    i = int(args[1])
                    while i > 0:
                        i -= 1
                        current_dir = Path(current_dir).parent
                    current_target = current_dir
                elif command == "object":
                    current_target = os.path.join(current_dir, args[1])
                    print(current_target)
                #content modifier
                elif command == "*content":
                    id_in_new = int(args[1])
                    id = -1
                    #correct id
                    if new_content_hashes_mapper[id_in_new] != -1:
                        #apply already inserted new hash
                        id = new_content_hashes_mapper[id_in_new]
                    else:
                        #try to insert new hash
                        id = -1
                        try:
                            id = content_hashes_stay.index(False)
                        except:
                            id = -1
                        # update or upload
                        salt = None
                        if id != -1:
                            #insert new hash
                            content_hashes_stay[id] = True
                            content_hashes[id] = new_content_hashes[id_in_new]
                            #write up current hashes
                            WriteNextHashes(id - file_hashes_next_id)
                            SkipHash()

                            #generate new entry
                            #get salt
                            salt = crypto.generate_salt()
                            #encrypt file
                            output_path = "temp_file.bin"
                            crypto.encrypt(current_target, output_path, salt)
                
                            #update in cloud
                            cloud.update(id + 1, current_target)

                        else:
                            #skip deleting and copy remaining hashes
                            while file_hashes_next_id < len(content_hashes):
                                args = dimp_hashes.Next()
                                file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1].strip()) + ";\n")
                                file_hashes_next_id += 1

                            #put new id
                            id = upload_id_gen
                            upload_id_gen += 1

                            #generate new entry
                            #get salt
                            salt = crypto.generate_salt()
                            #encrypt file
                            output_path = "temp_file.bin"
                            crypto.encrypt(current_target, output_path, salt)

                            #upload new file into the cloud
                            cloud.upload(id + 1, output_path)
                            
                        #write new hash
                        file_hashes.write(DimSanitize(new_content_hashes[id_in_new].hex()) + "," + DimSanitize(salt.hex()) + ";\n")
                        
                        #save new id
                        new_content_hashes_mapper[id_in_new] = id

                    #correct args
                    args[0] = "\ncontent"
                    args[1] = str(id)
        #write args
        WriteObject(args)
    #close objects.dim
    file_objects.close()
    #close objects_new.dim
    file_objects_new.close()
    del dimp

    #start deleting hashes that are not used
    while file_hashes_next_id < len(content_hashes):
        args = dimp_hashes.Next()
        if content_hashes_stay[file_hashes_next_id]:
            #save used hash
            file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1].strip()) + ";\n")
        else:
            #delete in the cloud
            cloud.delete(file_hashes_next_id + 1)
            #save empty hash
            file_hashes.write(",;\n")
        #next id
        file_hashes_next_id += 1
    #close hashes.dim
    file_hashes.close()
    #close combined.bin
    file_combined.close()
    del dimp_hashes

else:
    # First Upload:
    
    # init file hashes
    file_hashes = open("hashes.dim", "w")
    file_hashes.write("section,information;\n")
    file_hashes.write("title," + DimSanitize("Example Title") + ";\n")
    file_hashes.write("section,hashes;\n")

    # Generate objects.dim
    ScanObjects("./test_source", "objects.dim")

    # close hashes
    file_hashes.close()

# Finishing
PackManifest()
cloud.upload(0, "combined.bin")