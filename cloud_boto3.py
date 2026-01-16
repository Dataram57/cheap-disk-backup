import os
import shutil
import boto3

bucket_name = ""
prefix = ""
s3 = None


def initialize(config):
    global bucket_name
    global prefix
    global s3
    bucket_name = config["bucket_name"]
    prefix = config["prefix"]
    s3 = boto3.client(
        "s3",
        endpoint_url=config["endpoint_url"],
        aws_access_key_id=config["aws_access_key_id"],
        aws_secret_access_key=config["aws_secret_access_key"],
    )

def upload(id, file_path):
    print("Uploading:", id, file_path)
    try:
        s3.upload_file(Bucket=bucket_name, Key=prefix + str(id), Filename=file_path)
        return True
    except  Exception as e:
        print(e)
        return False

def update(id, file_path):
    print("Update--V")
    return upload(id, file_path)

def delete(id):
    print("Deleting:", id)
    try:
        s3.delete_object(Bucket=bucket_name, Key=prefix + str(id))
        return True
    except:
        print("error")
        return False

def download(id, file_path):
    print("Downloading:", id, file_path)
    try:
        s3.download_file(Bucket=bucket_name, Key=prefix + str(id), Filename=file_path)
        return True
    except:
        print("error")
        return False


"""
#message.txt
s3.put_object(Bucket=bucket_name, Key="message.txt", Body=b"Hello World")
print(s3.get_object(Bucket=bucket_name, Key="message.txt")["Body"].read())
s3.delete_object(Bucket=bucket_name, Key="message.txt")

#lizard.jpg
s3.upload_file(Bucket=bucket_name, Key="lizard.jpg", Filename="test.jpg")
s3.download_file(Bucket=bucket_name, Key="lizard.jpg", Filename="return.jpg")
s3.delete_object(Bucket=bucket_name, Key="lizard.jpg")
try:
    s3.delete_object(Bucket=bucket_name, Key="lizard.jpg")
except:
    print("file not found lol")
"""