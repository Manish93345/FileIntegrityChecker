# FOR CHECKING ONLY, IT JUST GENERATE HASH OF A FILE

import hashlib

def generate_file_hash(file_path, algorithm="sha256"):
    """
    Generate hash for the given file.
    Supported algorithms: sha256, sha512, md5 (not recommended)
    """
    hash_func = getattr(hashlib, algorithm)()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        return "Error: File not found."

if __name__ == "__main__":
    path = input("Enter file path: ")
    print("SHA256 Hash:", generate_file_hash(path))
