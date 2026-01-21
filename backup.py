from shared import *
import os
import stat
import hashlib
from pathlib import Path
import importlib
import shutil
from Dimperpreter import Dimperpreter
import struct
import json
import signal

BUFFER_SIZE = 8192
#default
FILENAME_TEMP = "temp_file.bin"
FILENAME_OBJECTS = "objects.dim"
FILENAME_HASHES = "hashes.dim"
FILENAME_COMBINED = "combined.dim"
FILENAME_COMBINED_ENCRYPTED = "combined.enc.bin"
FILENAME_COMBINED_FINAL = "combined.bin"
#Update
FILENAME_OBJECTS_TO_CORRECT = "objects_new.dim"

#ScanObjects
FILENAME_HASHES_NEW = "new_hashes.dim"

#OptimizeObjects
FILENAME_HASHES_NEW_MAP = "new_content_hashes_mapper.dim"

#================================================================
# Killing

toBeKilled = False
def KillMe(signum, frame):
    global toBeKilled
    print("Killing...")
    toBeKilled = True
signal.signal(signal.SIGINT, KillMe)

def CheckDeath():
    global toBeKilled
    if toBeKilled:
        print("Killed.")
        exit(0)
        return

#================================================================
# Load config and modules

with open("backup.config.json", "r") as f:
    config = json.load(f)

crypto = importlib.import_module(config["crypto"]["module"])
crypto.initialize(config["crypto"]["config"])
cloud = importlib.import_module(config["cloud"]["module"])
cloud.initialize(config["cloud"]["config"])

def EncryptFile(file_path, output_path, salt):
    #encrypt
    crypto.encrypt(file_path, output_path, salt)
    #add salt
    with open(output_path, "ab") as f:
         f.write(salt)

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
file_new_content_hashes = None


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
                #new hash found
                new_content_hashes.append(hash_bytes)
                new_content_hashes_mapper.append(-1)
                #save hash
                file_new_content_hashes.write(DimSanitize(hash_bytes.hex()) + ";\n")
                #return id
                return -len(new_content_hashes)
    else:
        try:
            return content_hashes.index(hash_bytes)
        except ValueError:
            #get salt
            salt = crypto.generate_salt(SALT_LENGTH)
            #encrypt file
            output_path = FILENAME_TEMP
            EncryptFile(file_path, output_path, salt)
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
    #check if there is a previous state to be loaded
    expectedDir = None
    expectedTarget = None
    if Path(output_path).is_file():
        #get last checked path
        with open(output_path, "r") as f:
            dimp = Dimperpreter(f)
            expectedDir = start_path
            expectedTarget = expectedDir
            while True:
                args = dimp.Next()
                if not args:
                    break
                match args[0].strip():
                    case "content":
                        content_hashes_stay[int(args[1])] = True
                    case "in":
                        expectedDir = os.path.join(expectedDir, args[1])
                        expectedTarget = expectedDir
                    case "out":
                        i = int(args[1])
                        while i > 0:
                            i -= 1
                            expectedDir = Path(expectedDir).parent
                        expectedTarget = expectedDir
                    case "object":
                        expectedTarget = os.path.join(expectedDir, args[1])
            #end
            print("ScanObjects:", "Previous state at", expectedTarget)
            del dimp
            f.close()
        #load new content hashes
        with open(FILENAME_HASHES_NEW, "r") as f:
            dimp = Dimperpreter(f)
            while True:
                args = dimp.Next()
                if not args:
                    break
                if len(args[0].strip()) > 0:
                    new_content_hashes.append(bytes.fromhex(args[0]))
                    new_content_hashes_mapper.append(-1)
            #end
            del dimp
            f.close()

    #file
    file_objects = open(output_path, "a")

    #funcs
    def WriteObject(*args):
        #skip
        if expectedTarget != None:
            return
        #write
        for i, arg in enumerate(args):
            file_objects.write(DimSanitize(arg))
            if i < len(args) - 1:
                file_objects.write(",")
        file_objects.write(";\n")

    #start scanning
    WriteObject("section", "objects")
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
            #get path
            path = os.path.join(root, name)
            
            if expectedTarget != None:
                print("=:", path)
            else:
                print("+:", path)

            #check if reached proper target
            if expectedTarget != None:
                if expectedTarget == path:
                    expectedTarget = None
                continue

            #rest
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

            #Break here
            CheckDeath()

#================================================================
# Manifest

def join_files(file1, file2, output):
    with open(output, "wb") as out:
        for fname in (file1, file2):
            with open(fname, "rb") as f:
                out.write(f.read())

def PackManifest():
    join_files(FILENAME_HASHES, FILENAME_OBJECTS, FILENAME_COMBINED)

    # get integrity hash
    integrity_hash = sha256_file(FILENAME_COMBINED)

    # encrypt combine
    salt = crypto.generate_salt(SALT_LENGTH)
    crypto.encrypt(FILENAME_COMBINED, FILENAME_COMBINED_ENCRYPTED, salt)

    # write file
    with open(FILENAME_COMBINED_FINAL, "wb") as out_file:
        #write hash + salt
        out_file.write(integrity_hash)
        out_file.write(struct.pack("I", len(salt)))
        out_file.write(salt)
        #write encrypted combined.dim
        with open(FILENAME_COMBINED_ENCRYPTED, "rb") as in_file:
            while True:
                chunk = in_file.read(BUFFER_SIZE)
                if not chunk:
                    break
                out_file.write(chunk)

def CreateEmptyManifest():
    f = open(FILENAME_HASHES, "w")
    f.write("section,hashes;\n")
    f.close()
    f = open(FILENAME_OBJECTS, "w")
    f.write("section,hashes;\n")
    f.close()
    PackManifest()
    os.remove(FILENAME_HASHES)
    os.remove(FILENAME_OBJECTS)

#================================================================
# Differential backup

#loads already existing hashes
def LoadArrays():
    #read headers
    file_combined = open(FILENAME_COMBINED_FINAL, "rb")
    integrity_hash = file_combined.read(32)
    length = struct.unpack("I", file_combined.read(4))[0]
    salt = file_combined.read(length)
    file_combined.close()
    #cut headers
    CUT = (0 + 32) + (4 + length)
    with open(FILENAME_COMBINED_FINAL, "rb") as src, open(FILENAME_COMBINED_ENCRYPTED, "wb") as dst:
        src.seek(CUT)
        shutil.copyfileobj(src, dst)
    #os.replace(FILENAME_COMBINED_ENCRYPTED, FILENAME_COMBINED_FINAL)
    #decrypt
    crypto.decrypt(FILENAME_COMBINED_ENCRYPTED, FILENAME_COMBINED, salt)
    #os.replace("combined_decrypted.bin", FILENAME_COMBINED_FINAL)

    #check integrity_hash
    if sha256_file(FILENAME_COMBINED) != integrity_hash:
        #perform
        print("hashes don't match")
    else:
        #load hashes
        file_combined = open(FILENAME_COMBINED, "r", encoding="utf-8")
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
    #read headers
    file_combined = open(FILENAME_COMBINED_FINAL, "rb")
    integrity_hash = file_combined.read(32)
    length = struct.unpack("I", file_combined.read(4))[0]
    salt = file_combined.read(length)
    file_combined.close()
    #cut headers
    CUT = (0 + 32) + (4 + length)
    with open(FILENAME_COMBINED_FINAL, "rb") as src, open(FILENAME_COMBINED_ENCRYPTED, "wb") as dst:
        src.seek(CUT)
        shutil.copyfileobj(src, dst)
    #os.replace(FILENAME_COMBINED_ENCRYPTED, FILENAME_COMBINED_FINAL)
    #decrypt
    crypto.decrypt(FILENAME_COMBINED_ENCRYPTED, FILENAME_COMBINED, salt)
    #os.replace("combined_decrypted.bin", FILENAME_COMBINED_FINAL)

    #check integrity_hash
    if sha256_file(FILENAME_COMBINED) != integrity_hash:
        #perform
        print("hashes don't match")
    else:
        #load hashes
        file_combined = open(FILENAME_COMBINED, "r", encoding="utf-8")
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

# Scans
#- FILENAME_COMBINED - to retrieve details about the old content
#- FILENAME_OBJECTS_TO_CORRECT - as a reference object hierarchy
#Produces:
#- FILENAME_HASHES - new list of hashes
#- FILENAME_OBJECTS - adjusted object hierarchy
def OptimizeContent(start_path):
    #current content id
    file_hashes_next_id = 0
    upload_id_gen = len(content_hashes)

    #check if there is a previous state to be loaded
    expectedDir = None
    expectedTarget = None
    expectedCombo = 0
    if Path(FILENAME_OBJECTS).is_file():
        #get last checked path
        with open(FILENAME_OBJECTS, "r") as f:
            dimp = Dimperpreter(f)
            expectedDir = start_path
            expectedTarget = expectedDir
            while True:
                args = dimp.Next()
                if not args:
                    break
                match args[0].strip():
                    case "in":
                        expectedDir = os.path.join(expectedDir, args[1])
                        expectedTarget = expectedDir
                        expectedCombo = 0
                    case "out":
                        i = int(args[1])
                        while i > 0:
                            i -= 1
                            expectedDir = Path(expectedDir).parent
                        expectedTarget = expectedDir
                        expectedCombo = 0
                    case "object":
                        expectedTarget = os.path.join(expectedDir, args[1])
                        expectedCombo = 0
                #count combo
                expectedCombo += 1
            #end
            print("OptimizeContent:", "Previous state at", expectedTarget)
            del dimp
            f.close()
        #get last count of written hashes
        with open(FILENAME_HASHES, "r") as f:
            dimp = Dimperpreter(f)
            #scope to proper section
            while True:
                args = dimp.Next()
                if args[0].strip() == "section":
                    if args[1].strip() == "hashes":
                        break
            #read hashes
            while True:
                args = dimp.Next()
                if not args:
                    break
                if len(args[0].strip()) > 0:
                    if file_hashes_next_id < len(content_hashes_stay):
                        content_hashes_stay[file_hashes_next_id] = True
                        file_hashes_next_id += 1
                    else:
                        #now uploading will most likely occur
                        upload_id_gen += 1
            del dimp
            f.close()
        #get last saved new_content_hashes_mapper
        with open(FILENAME_HASHES_NEW_MAP, "r") as f:
            i = 0
            dimp = Dimperpreter(f)
            while True:
                args = dimp.Next()
                if not args:
                    break
                if len(args[0].strip()) > 0:
                    new_content_hashes_mapper[i] = int(args[0].strip())
                    i += 1
            del dimp
            f.close()

    #objects.dim
    file_objects = open(FILENAME_OBJECTS, "a", encoding="utf-8")
    def WriteObject(args):
        for i, arg in enumerate(args):
            file_objects.write(DimSanitize(arg))
            if i < len(args) - 1:
                file_objects.write(",")
        file_objects.write(";")
    
    #hashes.dim
    file_hashes = open(FILENAME_HASHES, "a")
    #write headers
    if expectedTarget == None:
        file_hashes.write("section,information;\n")
        file_hashes.write("title," + DimSanitize("Example Title") + ";\n")
        file_hashes.write("section,hashes;\n")

    #main reference file
    file_combined = open(FILENAME_COMBINED, "r", encoding="utf-8")
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
    def WriteNextHashes(count):
        nonlocal file_hashes_next_id
        while count > 0:
            count -= 1
            args = dimp_hashes.Next()
            file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1]) + ";\n")
            file_hashes_next_id += 1
    def SkipHash():
        nonlocal file_hashes_next_id
        dimp_hashes.Next()
        file_hashes_next_id += 1

    #mapper.dim
    file_mapper = open(FILENAME_HASHES_NEW_MAP, "a", encoding="utf-8")

    #scan objects_new.dim
    file_objects_new = open(FILENAME_OBJECTS_TO_CORRECT, "r", encoding="utf-8")
    dimp = Dimperpreter(file_objects_new)
    section = ""
    current_dir = start_path
    current_target = current_dir
    current_combo = 0
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
                    current_combo = 0
                elif command == "out":
                    i = int(args[1])
                    while i > 0:
                        i -= 1
                        current_dir = Path(current_dir).parent
                    current_target = current_dir
                    current_combo = 0
                elif command == "object":
                    current_target = os.path.join(current_dir, args[1])
                    current_combo = 0
                    print(current_target)
                
                #update combo
                current_combo += 1

                #content modifier
                #skip if we are searching for the proper target
                if expectedTarget != None:
                    if expectedTarget == current_target:
                        if expectedCombo == current_combo: 
                            expectedTarget = None
                    #small print
                    if command == "*content":
                        print("Already uploaded.")
                    continue
                else:
                    #only if we have reached the target we had not saved before
                    #content modifier
                    if command == "*content":
                        #log
                        print("cloud <--", current_target)
                        #vars
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
                            # update/upload or upload
                            salt = None
                            if id != -1:
                                #check if hash is empty
                                doUpload = (len(content_hashes[id]) == 0)

                                #generate new entry
                                #get salt
                                salt = crypto.generate_salt(SALT_LENGTH)
                                #encrypt file
                                output_path = FILENAME_TEMP
                                EncryptFile(current_target, output_path, salt)
                                
                                #update in cloud
                                if doUpload:
                                    cloud.upload(id + 1, output_path)
                                else:
                                    cloud.update(id + 1, output_path)

                                #TODO: HANDLE FAILURES

                                #insert new hash
                                content_hashes_stay[id] = True
                                content_hashes[id] = new_content_hashes[id_in_new]
                                #write up current hashes
                                WriteNextHashes(id - file_hashes_next_id)
                                SkipHash()

                            else:
                                #put new id
                                id = upload_id_gen
                                upload_id_gen += 1

                                #generate new entry
                                #get salt
                                salt = crypto.generate_salt(SALT_LENGTH)
                                #encrypt file
                                output_path = FILENAME_TEMP
                                EncryptFile(current_target, output_path, salt)

                                #upload new file into the cloud
                                cloud.upload(id + 1, output_path)

                                #TODO: HANDLE FAILURES

                                #skip deleting and copy remaining hashes
                                while file_hashes_next_id < len(content_hashes):
                                    args = dimp_hashes.Next()
                                    file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1].strip()) + ";\n")
                                    file_hashes_next_id += 1
                                
                            #write new hash
                            file_hashes.write(DimSanitize(new_content_hashes[id_in_new].hex()) + "," + DimSanitize(salt.hex()) + ";\n")
                            
                            #save new id
                            new_content_hashes_mapper[id_in_new] = id
                            file_mapper.write(DimSanitize(str(id)) + ";") #safe for this kind of scanning

                        #correct args
                        args[0] = "\ncontent"
                        args[1] = str(id)
        #write args
        WriteObject(args)

        #Break here
        CheckDeath()

    #close objects.dim
    file_objects.close()
    #close objects_new.dim
    file_objects_new.close()
    del dimp

    #start deleting hashes that are not used
    #find id first element that has next elements all to be deleted
    print("Cleaning up unused content.")
    id = len(content_hashes) - 1
    while id >= file_hashes_next_id:
        #check if end
        if content_hashes_stay[id]:
            break
        #delete this last file (if it hasn't been already deleted)
        if len(content_hashes[id]) != 0:
            cloud.delete(id + 1)


            #TODO: HANDLE ERRORS


        #next
        id -= 1
    #save elment till id of non empty element is
    while file_hashes_next_id <= id:
        args = dimp_hashes.Next()
        if content_hashes_stay[file_hashes_next_id]:
            #save used hash
            file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1].strip()) + ";\n")
        else:
            #delete in the cloud (if hasn't been already deleted)
            if len(content_hashes[file_hashes_next_id]) != 0:
                cloud.delete(file_hashes_next_id + 1)
                
                
                #TODO: HANDLE ERRORS


            #save empty hash
            file_hashes.write(",;\n")
        #next id
        file_hashes_next_id += 1
    #close hashes.dim
    file_hashes.close()
    #close combined.bin
    file_combined.close()
    del dimp_hashes

#================================================================
# Main

is_update = True

#check if empty manifest has to be made.
if not Path(FILENAME_COMBINED_FINAL).is_file():
    if not cloud.download(0, FILENAME_COMBINED_FINAL):
        CreateEmptyManifest()
#load existing hashes
LoadArrays()
#Generate new hashes and load objects (failure may occur here)
file_new_content_hashes = open(FILENAME_HASHES_NEW, "a")
ScanObjects(config["targetSourceDirectory"], FILENAME_OBJECTS_TO_CORRECT)
file_new_content_hashes.close()
#Optimize content
OptimizeContent(config["targetSourceDirectory"])

# Finishing
PackManifest()
cloud.upload(0, FILENAME_COMBINED_FINAL)