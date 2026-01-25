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
import time

BUFFER_SIZE = 8192
INTEGRITY_HASH_LENGTH = 32
SALT_LENGTH = 1024
#default
FILENAME_TEMP = "backup_temp_file.bin"
FILENAME_TEMP_ORIGINAL = "backup_temp_file_original.bin"
FILENAME_OBJECTS = "backup_objects.dim"
FILENAME_HASHES = "backup_hashes.dim"
FILENAME_COMBINED = "backup_combined.dim"
FILENAME_COMBINED_ENCRYPTED = "backup_combined.dim.enc"
FILENAME_COMBINED_FINAL = "backup_combined.bin"
FILENAME_COMBINED_FINAL_UPLOAD = "backup_combined_upload.bin"
#Update
FILENAME_OBJECTS_TO_CORRECT = "backup_objects_new.dim"

#ScanObjects
FILENAME_HASHES_NEW = "backup_new_hashes.dim"

#OptimizeObjects
FILENAME_HASHES_NEW_MAP = "backup_new_content_hashes_mapper.dim"

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

def JudgeTransaction(result, failureCommand):
    #positive case
    if result:
        return True
    #wrong cases
    print("Recent transaction failed.")
    failureCommand = failureCommand.strip().split(" ")
    match failureCommand[0]:
        case "stop":
            print("Exitting...")
            exit(0)
        case "wait":
            print("Waiting", failureCommand[1], "seconds...")
            time.sleep(float(failureCommand[1]))
    #return
    return False

from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern
ignore_include = PathSpec.from_lines(GitWildMatchPattern, config["ignore"]["include"])
ignore_exclude = PathSpec.from_lines(GitWildMatchPattern, config["ignore"]["exclude"])
def isIgnored(path) -> bool:
    # First: does it match any ignore rule?
    if not ignore_include.match_file(path):
        return False

    # Second: is it explicitly excluded (un-ignored)?
    if ignore_exclude.match_file(path):
        return False

    return True

SALT_LENGTH = int(config["crypto"]["saltLength"])

#================================================================
# Manifest

def DimSanitize(arg):
    return str(arg).replace("@", "@@").replace(",", "@,").replace(";", "@;")

#================================================================
# Additional

userIDs = []
groupIDs = []

#================================================================
# Content Hashes

content_hashes = []         #store only hashes (salt is applied elsewhere)
content_hashes_stay = []    #store only Booleans to mark if cloud stored content is still up to date
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
    last_root = start_path
    root_relative = ""
    for root, dirs, files in os.walk(start_path, onerror=lambda e: None, followlinks=False):
        #check what kind of step
        if last_root != root:
            r = cd_up(last_root, root)
            if r > 0:
                WriteObject("out", r)
                while r > 0:
                    r -= 1
                    root_relative = Path(root_relative).parent
            WriteObject("in", os.path.basename(root))
            last_root = root
            root_relative = os.path.join(root_relative, os.path.basename(root))

            #check if dir is skipped
            if isIgnored(root_relative):
                print("Ignored.")
                continue

            #register dir info
            st = os.lstat(root)
            WriteObject("stat", st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns)

        #study files
        for name in files + dirs:
            #get path
            path = os.path.join(root, name)
            pathRelative = os.path.join(root_relative, name)
            
            if expectedTarget != None:
                print("Discovery Saved:", pathRelative)
            else:
                print("Discovered:", pathRelative)

            #check if reached proper target
            if expectedTarget != None:
                if expectedTarget == path:
                    expectedTarget = None
                continue
            
            #ignore
            if isIgnored(pathRelative):
                print("Ignored.")
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

    # write integrity hash
    integrity_hash = sha256_file(FILENAME_COMBINED)
    with open(FILENAME_COMBINED, "ab") as out_file:
        out_file.write(integrity_hash)

    # encrypt combine
    salt = crypto.generate_salt(SALT_LENGTH)
    crypto.encrypt(FILENAME_COMBINED, FILENAME_COMBINED_ENCRYPTED, salt)

    # write file
    with open(FILENAME_COMBINED_FINAL_UPLOAD, "wb") as out_file:
        #write encrypted combined.dim
        with open(FILENAME_COMBINED_ENCRYPTED, "rb") as in_file:
            while True:
                chunk = in_file.read(BUFFER_SIZE)
                if not chunk:
                    break
                out_file.write(chunk)
        #write salt
        out_file.write(salt)

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
    os.replace(FILENAME_COMBINED_FINAL_UPLOAD, FILENAME_COMBINED_FINAL)

#================================================================
# Differential backup

#loads already existing hashes
def LoadArrays():
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
    global config

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
                    #print(current_target)
                
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
                        #print("Adding to cloud:", current_target)
                        #vars
                        id_in_new = int(args[1])
                        id = -1
                        #correct id
                        if new_content_hashes_mapper[id_in_new] != -1:
                            #apply already inserted new hash
                            id = new_content_hashes_mapper[id_in_new]
                            #print("Already uploaded.")
                        else:
                            print("Adding to cloud:", current_target)
                            #copy file to temporary safe space...
                            
                            #check if file exists
                            #if not then: reject all with the same content hash

                            #recalculate hash (no problem, except suspicions of replay attacks on restore.py)
                            #if hash doesn't match then: reject all with the same content hash

                            #id for rejection might be: -2
                            #+also change these:
                            # new_content_hashes[id_in_new] = b''
                            # salt = b''

                            #copy file
                            id = -1
                            try:
                                #copy file
                                shutil.copy(current_target, FILENAME_TEMP_ORIGINAL)
                                #check hash again
                                if sha256_file(FILENAME_TEMP_ORIGINAL) != new_content_hashes[id_in_new]:
                                    print(sha256_file(FILENAME_TEMP_ORIGINAL).hex(), new_content_hashes[id_in_new].hex())
                                    raise
                                #try to insert new hash
                                id = -1
                                try:
                                    id = content_hashes_stay.index(False)
                                except:
                                    id = -1
                            except:
                                id = -2
                            # update/upload or upload
                            salt = None
                            if id >= 0:

                                #generate new entry
                                #get salt
                                salt = crypto.generate_salt(SALT_LENGTH)
                                #encrypt file
                                output_path = FILENAME_TEMP
                                EncryptFile(FILENAME_TEMP_ORIGINAL, output_path, salt)
                                
                                #update in cloud
                                if len(content_hashes[id]) == 0:
                                    #hash is empty, so upload
                                    while True:
                                        if JudgeTransaction(cloud.upload(id + 1, output_path), config["cloud"]["onUploadError"]):
                                            break
                                else:
                                    #update
                                    while True:
                                        if JudgeTransaction(cloud.update(id + 1, output_path), config["cloud"]["onUpdateError"]):
                                            break

                                #insert new hash
                                content_hashes_stay[id] = True
                                content_hashes[id] = new_content_hashes[id_in_new]
                                #write up current hashes
                                WriteNextHashes(id - file_hashes_next_id)
                                SkipHash()

                            elif id == -1:
                                #put new id
                                id = upload_id_gen
                                upload_id_gen += 1

                                #generate new entry
                                #get salt
                                salt = crypto.generate_salt(SALT_LENGTH)
                                #encrypt file
                                output_path = FILENAME_TEMP
                                EncryptFile(FILENAME_TEMP_ORIGINAL, output_path, salt)

                                #upload new file into the cloud
                                while True:
                                    if JudgeTransaction(cloud.upload(id + 1, output_path), config["cloud"]["onUploadError"]):
                                        break

                                #skip deleting and copy remaining hashes
                                while file_hashes_next_id < len(content_hashes):
                                    args = dimp_hashes.Next()
                                    file_hashes.write(DimSanitize(args[0].strip()) + "," + DimSanitize(args[1].strip()) + ";\n")
                                    file_hashes_next_id += 1
                            
                            else:
                                #reject hash
                                print("Altered content detected - Rejecting upload of this content!!!")
                                salt = b''
                                new_content_hashes[id_in_new] = b'' #only to write this bad hash (next will simply reference -2)


                            #write new hash (only if in proper)
                            if id >= 0:
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
while True:
    if JudgeTransaction(cloud.upload(0, FILENAME_COMBINED_FINAL_UPLOAD), config["cloud"]["onUploadError"]):
        break

#================================================================
# Cleaning

#delete saved files
def DeleteFile(path):
    try:
        os.remove(path)
    except:
        0
DeleteFile(FILENAME_TEMP)
DeleteFile(FILENAME_TEMP_ORIGINAL)
DeleteFile(FILENAME_OBJECTS)
DeleteFile(FILENAME_HASHES)
DeleteFile(FILENAME_COMBINED)
DeleteFile(FILENAME_COMBINED_ENCRYPTED)
DeleteFile(FILENAME_COMBINED_FINAL)
DeleteFile(FILENAME_COMBINED_FINAL_UPLOAD )
#Update
DeleteFile(FILENAME_OBJECTS_TO_CORRECT)
#ScanObjects
DeleteFile(FILENAME_HASHES_NEW)
#OptimizeObjects
DeleteFile(FILENAME_HASHES_NEW_MAP)