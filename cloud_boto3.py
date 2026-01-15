import os
import shutil
import json
import boto3

with open("cloud_boto3.config.json", "r") as f:
    config = json.load(f)
bucket_name = config["bucket_name"]
endpoint_url = config["endpoint_url"]
aws_access_key_id = config["aws_access_key_id"]
aws_secret_access_key = config["aws_secret_access_key"]

s3 = boto3.client(
    "s3",
    endpoint_url=endpoint_url,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

def initialize():
    0

def upload(id, file_path):
    print("Uploading:", id, file_path)
    try:
        s3.upload_file(Bucket=bucket_name, Key=str(id), Filename=file_path)
        return True
    except:
        return False

def update(id, file_path):
    return upload(id, path)

def delete(id):
    print("Deleting:", id)
    try:
        s3.delete_object(Bucket=bucket_name, Key=str(id))
        return True
    except:
        return False

def download(id, file_path):
    print("Downloading:", id, file_path)
    try:
        s3.download_file(Bucket=bucket_name, Key=str(id), Filename=file_path)
        return True
    except:
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