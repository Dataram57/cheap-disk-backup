import os
import shutil

def upload(id, file_path):
    try:
        shutil.copy2(file_path, "./test_cloud/" + str(id))
        return True
    except:
        return False

def replace(id, file_path):
    try:
        shutil.copy2(file_path, "./test_cloud/" + str(id))
        return True
    except:
        return False

def delete(id):
    try:
        os.remove("./test_cloud/" + str(id))
        return True
    except:
        return False

def download(id, file_path):
    try:
        shutil.copy2("./test_cloud/" + str(id), file_path)
        return True
    except:
        return False
