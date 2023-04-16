import argparse
import hashlib
import os
import shutil
import sys
import time
from typing import Optional, List

import requests

from src.Tidy import Tidy
from src.Tidy import FileRenamer
from src.Tidy import generate_fingerprint

# THESE WILL BE MOVED TO HELPER MODULE

INPUT = 'data/input/'
OUTPUT = 'output/'
DATA = 'data/'

def copy_files(source_files: List[str], destination_folder: str) -> None:
    '''
    Copy a list of files to a new destination folder.

    Args:
    source_files (List[str]): A list of file paths to be copied.
    destination_folder (str): The path of the destination folder.

    Raises:
    FileNotFoundError: If the source file(s) do not exist.
    FileExistsError: If the destination folder already exists as a file.
    '''

    # Check if the destination folder exists, create it if missing
    if not os.path.isdir(destination_folder):
        os.makedirs(destination_folder)

    # Copy each file to the destination folder
    for file in source_files:
        if not os.path.isfile(file):
            raise FileNotFoundError(f"{file} does not exist.")
        destination = os.path.join(destination_folder, os.path.basename(file))
        shutil.copy2(file, destination)

def copy_directory(src_dir: str, dest_dir: str, overwrite: Optional[bool] = False) -> None:
    '''
    Copy a directory and all its contents to a new destination.

    Args:
    src_dir (str): The path of the directory to be copied.
    dest_dir (str): The path of the destination directory to copy the directory to.
    overwrite (bool): Whether or not to overwrite the destination directory if it already exists.
    
    Raises:
    FileNotFoundError: If the source directory does not exist.
    FileExistsError: If the destination directory already exists.
    '''
    if not os.path.exists(src_dir):
        raise FileNotFoundError(f"Source directory '{src_dir}' does not exist.")

    if os.path.exists(dest_dir):
        if not overwrite:
            raise FileExistsError(f"Destination directory '{dest_dir}' already exists.")

        shutil.rmtree(dest_dir)

    shutil.copytree(src_dir, dest_dir)


def rename_chunks(file_name: str, dir_path: str) -> None:
    '''
    Renames files in a directory with salted hash-based name.

    Args:
    file_name (str): The name of the file to be renamed.
    dir_path (str): The path to the directory containing the file.

    Returns:
    None
    '''
    dir_path = dir_path
    salt_hash_algo = "sha256"
    file_renamer = FileRenamer(dir_path, salt_hash_algo)
    file_renamer.rename_files()
    file_renamer.write_file_hashes_to_json(f'{file_name}.json')


def create_folder_from_file(file_path: str) -> str:
    '''
    Creates a folder based on the SHA256 hash of the given file.

    Args:
    file_path (str): The path of the file to be hashed and used as the folder name.

    Returns:
    str: The name of the created folder.
    '''
    # Calculate the SHA256 hash of the file
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    print(f'Hashing File: {file_path} >> {file_hash}')

    # Create a folder with the first 9 characters of the hash as its name
    folder_name = file_hash[:9]
    print(f'Using first 9 as folder name: {folder_name}')
    os.makedirs(f'{DATA}{folder_name}')

    return folder_name

def move_and_delete_file(source: str, destination: str) -> None:
    """
    Move a file from source to destination and delete the original file.

    Args:
        source (str): The source path of the file.
        destination (str): The destination path of the file.

    Returns:
        None
    """
    shutil.move(source, destination)
    print(f'{source} moved to {destination}')
    #os.remove(source)

def print_report(docSplit: str) -> None:
    """
    Print a report of the file paths created during file encryption.

    Args:
        docSplit (str): The base file name for the report.

    Returns:
        None
    """
    encrypted_doc = f'{docSplit}.tidy' 
    key_out = f'{docSplit}.tkey'
    rubbish_output = f'{docSplit}.trubbish'
    chunks_folder = f'{docSplit}_chunks'
    division_name = f'{chunks_folder}/{docSplit}_chuck_'
    tar_in = f'{docSplit}.tar'
        
    tar_name = f'{docSplit}.tidy.tar'
    tar_key = f'{docSplit}.tkey.tar'
    
    print(f'Encrypted File: {encrypted_doc}\nEncrypted File Key: {key_out}\nRubbish Output: {rubbish_output}\nChunks Folder: {chunks_folder}\nTar: {tar_in}\nFinal Encrypted Folder: {tar_name}\nFinal Encrypted Folder Key: {tar_key}')

def main() -> None:
	"""
	This is only used for testing. Most the helper functions will be moved to helper.py
	"""

	parser = argparse.ArgumentParser(description='Encrypt a file with XOR encryption')

	parser.add_argument('file_to_encrypt', type=str, help='Path to the file to be encrypted')
	parser.add_argument('entropy', type=float, help='Shannon entropy value for the encryption key')
	parser.add_argument('rubbish_length', type=int, help='Length of the randomly generated key prefix')
	parser.add_argument('chunk_size', type=int, help='Size of chunks to read from the input file')
	parser.add_argument('fingerprint', type=str, help='Fingerprint config to use for the output file')
	parser.add_argument('seed', type=int, help='Seed to use for the random number generator')

	args = parser.parse_args()
	fingerprint = generate_fingerprint(args.fingerprint)
	print(f'Using {fingerprint} as fingerprint')
	start = time.time()
	_tidy = Tidy()

	_file = args.file_to_encrypt
	if "." in _file:
		move_and_delete_file(_file, _file.split(".")[0])
		_file = _file.split(".")[0]
	# THIS IS VERY CONFUSING. CLEAN LATER
	folder_name = create_folder_from_file(_file)
	print("Created folder:", folder_name)
	move_and_delete_file(_file, f'{DATA}{folder_name}/{_file}')
	os.chdir(f'{DATA}{folder_name}')
	print(f'Changing Directory to {DATA}{folder_name}')
	_tidy.encrypt(_file, args.entropy, args.rubbish_length, args.chunk_size)

	tarName = f'{_file}.tidy.tar'
	tarkey = f'{_file}.tkey.tar'

	key = open(tarkey, 'r')
	
	

	g = _tidy.timeStamp(tarName, fingerprint, 'linking', args.seed, key.readlines())
	key.close()

	#print(g)
	#print('*'*50)

	_tidy.hash_time_stamp(g)

	#print(g)


	print('*'*50)
	n = _tidy.calPrime(516)
	push = _tidy.push_time_stamp(g, n)
	print(f'Using {n} for Segment' )
	#print(push)
	#print(g)
	with open('seg_file', 'w+') as f:
		f.write(str(push))
		f.close()
	print('Segment ID File Created: seg_file')
	with open('seg_file_un', 'w+') as f:
		f.write(str(g))
		f.close()

	print('Unencrypted Segment ID File Created: un_seg_file')
	#print('*'*50)
	#print(n)
	print_report(_file)
	end = time.time()
	# cuda.profile_stop()
	rename_chunks(_file, f'{_file}_chunks')
	#copy_directory(folder_name, f'data/input/{folder_name}')
	files_to_copy = [tarName, tarkey, 'seg_file']
	copy_files(files_to_copy, f'{OUTPUT}')
	print("The time of execution of above program is :",
		(end-start) * 10**3, "ms")

if __name__ == '__main__':
	main()