import os
import shutil

def initialize():
    0

def upload(id, file_path):
    print("Uploading:", id, file_path)
    try:
        shutil.copy2(file_path, "./test_cloud/" + str(id))
        return True
    except:
        return False

def update(id, file_path):
    print("Updating:", id, file_path)
    try:
        shutil.copy2(file_path, "./test_cloud/" + str(id))
        return True
    except:
        return False

def delete(id):
    print("Deleting:", id)
    try:
        os.remove("./test_cloud/" + str(id))
        return True
    except:
        return False

def download(id, file_path):
    print("Downloading:", id, file_path)
    try:
        shutil.copy2("./test_cloud/" + str(id), file_path)
        return True
    except:
        return False
