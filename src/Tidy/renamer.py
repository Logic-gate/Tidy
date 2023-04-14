import os
import hashlib
import json
from typing import Dict


class FileRenamer:
    def __init__(self, dir_path: str, salt_hash_algo: str) -> None:
        self.dir_path = dir_path
        self.salt_hash_algo = salt_hash_algo
        self.file_dict: Dict[str, Dict[str, str]] = {}

    def calculate_file_hash(self, filepath: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def calculate_salt(self, file_hash: str) -> str:
        hash_func = getattr(hashlib, self.salt_hash_algo)
        salt_hash = hash_func(file_hash.encode()).hexdigest()
        return salt_hash

    def rename_files(self) -> None:
        for filename in os.listdir(self.dir_path):
            # Get the full path of the file
            filepath = os.path.join(self.dir_path, filename)

            # Calculate the SHA256 hash of the file
            file_hash = self.calculate_file_hash(filepath)

            # Calculate the salt using the given hash algorithm
            salt = self.calculate_salt(file_hash)

            # Add the salt to the original filename hash
            filename_hash = hashlib.sha256(filename.encode()).hexdigest()
            file_hash_salt = hashlib.sha256((filename_hash + salt).encode()).hexdigest()

            # Rename the file to the new hash + salt name
            new_filename = file_hash_salt + os.path.splitext(filename)[1]
            os.rename(filepath, os.path.join(self.dir_path, new_filename))

            # Add the old and new file names to the dictionary
            self.file_dict[filename] = {"new_name": new_filename, "hash": file_hash_salt, "salt": salt}

    def write_file_hashes_to_json(self, output_file: str) -> None:
        with open(output_file, "w") as f:
            json.dump(self.file_dict, f, indent=4)

