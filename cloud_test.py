import os
import shutil


def upload(id, file_path):
    shutil.copy2(file_path, "./test_cloud/" + str(id))

def replace(id, file_path):
    shutil.copy2(file_path, "./test_cloud/" + str(id))

def delete(id):
    os.remove("./test_cloud/" + str(id))
