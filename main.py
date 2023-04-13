import argparse
from tidy import tidy
import time
import hashlib
import os
import shutil

def create_folder_from_string(s):
    # Calculate the SHA256 hash of the string
    sha256 = hashlib.sha256(s.encode()).hexdigest()
    print(f'Hashing File Name: {s} >> {sha256}')

    # Create a folder with the first 9 characters of the hash as its name
    folder_name = sha256[:9]
    print(f'Using first 9 as folder name: {folder_name}')
    os.makedirs(folder_name)

    return folder_name

def move_and_delete_file(source, destination):
    # Move the file to the new destination
    shutil.move(source, destination)
    print(f'{source} moved to {destination}')
    # Delete the original file
def print_report(docSplit):
	encryptedDoc = f'{docSplit}.tidy' 
	key_out = f'{docSplit}.tkey'
	RubbishOutput = f'{docSplit}.trubbish'
	chunks_folder = f'{docSplit}_chunks'
	division_name = f'{chunks_folder}/{docSplit}_chuck_'
	tarIN = f'{docSplit}.tar'
		
	tarName = f'{docSplit}.tidy.tar'
	tarkey = f'{docSplit}.tkey.tar'
	
	print(f'Encrypted File: {encryptedDoc}\nEncrypted File Key: {key_out}\nRubbish Output: {RubbishOutput}\nChunks Folder: {chunks_folder}\nTar: {tarIN}\nFinal Encrypted Folder: {tarName}\nFinal Encrypted Folder Key: {tarkey}')

def main():
	parser = argparse.ArgumentParser(description='Encrypt a file with XOR encryption')

	parser.add_argument('file_to_encrypt', type=str, help='Path to the file to be encrypted')
	parser.add_argument('entropy', type=float, help='Shannon entropy value for the encryption key')
	parser.add_argument('rubbish_length', type=int, help='Length of the randomly generated key prefix')
	parser.add_argument('chunk_size', type=int, help='Size of chunks to read from the input file')
	parser.add_argument('fingerprint', type=str, help='Fingerprint to use for the output file')
	parser.add_argument('seed', type=int, help='Seed to use for the random number generator')

	args = parser.parse_args()

	start = time.time()
	_tidy = tidy()

	_file = args.file_to_encrypt
	if "." in _file:
		move_and_delete_file(_file, _file.split(".")[0])
		_file = _file.split(".")[0]
	folder_name = create_folder_from_string(_file)
	print("Created folder:", folder_name)
	move_and_delete_file(_file, f'{folder_name}/{_file}')
	os.chdir(folder_name)
	print(f'Changing Directory to {folder_name}')
	_tidy.encrypt(_file, args.entropy, args.rubbish_length, args.chunk_size)

	tarName = f'{_file}.tidy.tar'
	tarkey = f'{_file}.tkey.tar'

	key = open(tarkey, 'r')
		
	g = _tidy.timeStamp(tarName, args.fingerprint, 'linking', args.seed, key.readlines())
	key.close()

	#print(g)
	#print('*'*50)

	_tidy.hashTimeStamp(g)

	#print(g)

	
	print('*'*50)
	n = _tidy.calPrime(516)
	push = _tidy.pushTimeStamp(g, n)
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

	print("The time of execution of above program is :",
		(end-start) * 10**3, "ms")



if __name__ == '__main__':
	main()