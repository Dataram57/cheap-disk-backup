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

arr = []

file_combined = open("backup_hashes.dim", "r", encoding="utf-8")
dimp_hashes = Dimperpreter(file_combined)

while True:
    args = dimp_hashes.Next()
    #print(args)
    try:

        arr.index(args[0].strip())
        if args[0].strip() != "section":
            print("error!!!!!", args[0])
            exit(0)
    except:
        arr.append(args[0].strip())