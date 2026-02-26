import os
import stat

def secure_file(filepath):
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
