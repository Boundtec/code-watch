import os

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
print(len(key))
